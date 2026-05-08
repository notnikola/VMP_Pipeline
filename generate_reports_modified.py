import argparse
import pandas as pd
import plotly.graph_objects as go
import os
from jinja2 import Environment, FileSystemLoader


def load_and_preprocess_data(file_path, reporting_date=None):
    try:
        df = pd.read_csv(file_path, low_memory=False)

        df['First Detected (GMT -4)'] = pd.to_datetime(df['First Detected'])
        df['Last Detected (GMT -4)'] = pd.to_datetime(df['Last Detected'])

        if 'Names' in df.columns:
            df['Device Names'] = df['Names'].apply(lambda x: [name.strip() for name in str(x).split(',')])
        else:
            df['Device Names'] = [[] for _ in range(len(df))]

        as_of = reporting_date or pd.Timestamp.now()
        df['Vulnerability Age'] = (as_of - df['First Detected (GMT -4)']).dt.days

        df['Time to Resolve (Days)'] = pd.NA
        resolved_mask = df['Status'] == 'Resolved'
        df.loc[resolved_mask, 'Time to Resolve (Days)'] = (
            df['Last Detected (GMT -4)'] - df['First Detected (GMT -4)']
        ).dt.days

        if 'Vulnerability Recommended Steps' in df.columns:
            df['Vulnerability Recommended Steps'] = (
                df['Vulnerability Recommended Steps']
                .astype(str)
                .replace({'<': '&lt;', '>': '&gt;'}, regex=True)
                .replace('nan', '', regex=True)
            )

        df = df.dropna(subset=['Boundaries'])
        df = df[df['Boundaries'] != '']

        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        df['AVM Rating'] = pd.Categorical(df['AVM Rating'], categories=severity_order, ordered=True)

        return df, aggregate_cve_data(df, reporting_date)
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None, None
    except KeyError as e:
        print(f"Error: Missing expected column in CSV: {e}")
        return None, None
    except Exception as e:
        print(f"An unexpected error occurred during data loading: {e}")
        return None, None


def aggregate_cve_data(df, reporting_date=None):
    """Aggregates instance-level data into CVE-level summaries."""
    cve_df = df.groupby('Vulnerability CVE UID').agg(
        open_instances=('Status', lambda x: (x == 'Open').sum()),
        remediated_instances=('Status', lambda x: (x == 'Resolved').sum()),
        earliest_first_detected=('First Detected (GMT -4)', 'min'),
        latest_last_detected=('Last Detected (GMT -4)', 'max')
    ).reset_index()

    as_of = reporting_date or pd.Timestamp.now()
    cve_df['CVE_Age_Days'] = (as_of - cve_df['earliest_first_detected']).dt.days

    cve_df['Remediation_Date'] = pd.NA
    fully_remediated_mask = (cve_df['open_instances'] == 0) & (cve_df['remediated_instances'] > 0)
    cve_df.loc[fully_remediated_mask, 'Remediation_Date'] = cve_df.loc[fully_remediated_mask, 'latest_last_detected']
    cve_df['Remediation_Date'] = cve_df['Remediation_Date'].fillna('Not Remediated')

    cve_recommendations = (
        df.groupby('Vulnerability CVE UID')['Vulnerability Recommended Steps']
        .apply(lambda x: x.iloc[0] if not x.empty else '')
        .reset_index()
    )
    cve_df = pd.merge(cve_df, cve_recommendations, on='Vulnerability CVE UID', how='left')

    return cve_df


def filter_data_by_team(df, team_name, division=None):
    filtered = df[df['Boundaries'].str.contains(team_name, case=False, na=False)]
    if division is not None:
        filtered = filtered[filtered['Division'] == division]
    return filtered.copy()


def group_data_by_severity(df):
    return {severity: df[df['AVM Rating'] == severity].copy()
            for severity in df['AVM Rating'].cat.categories if severity in df['AVM Rating'].unique()}


def create_average_open_vulnerability_age_chart(cve_df_severity, severity_name):
    if cve_df_severity.empty:
        return None

    df_open_cves = cve_df_severity[cve_df_severity['open_instances'] > 0].copy()
    if df_open_cves.empty:
        return None

    df_open_cves['First Detected Month'] = df_open_cves['earliest_first_detected'].dt.to_period('M').dt.to_timestamp()
    monthly_avg = df_open_cves.groupby('First Detected Month')['CVE_Age_Days'].mean().reset_index()

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=monthly_avg['First Detected Month'],
        y=monthly_avg['CVE_Age_Days'],
        mode='lines+markers',
        name='Average Age of Open Vulnerabilities',
        line=dict(color='green', width=2)
    ))
    fig.update_layout(
        title=f'Average Age of Open Vulnerabilities by Month ({severity_name})',
        xaxis_title='Month',
        yaxis_title='Average Vulnerability Age (Days)',
        showlegend=True,
        template='plotly_dark'
    )
    return fig.to_html(full_html=False, include_plotlyjs='cdn')


def create_average_time_to_resolve_chart(cve_df_severity, severity_name):
    if cve_df_severity.empty:
        return None

    df_remediated = cve_df_severity[
        (cve_df_severity['open_instances'] == 0) &
        (cve_df_severity['remediated_instances'] > 0)
    ].copy()
    if df_remediated.empty:
        return None

    df_remediated['Remediation_Date'] = pd.to_datetime(df_remediated['Remediation_Date'])
    df_remediated['Time to Resolve (Days)'] = (
        df_remediated['Remediation_Date'] - df_remediated['earliest_first_detected']
    ).dt.days
    df_remediated = df_remediated[df_remediated['Time to Resolve (Days)'] >= 0].copy()
    if df_remediated.empty:
        return None

    df_remediated['Remediation Month'] = df_remediated['Remediation_Date'].dt.to_period('M').dt.to_timestamp()
    monthly_avg = df_remediated.groupby('Remediation Month')['Time to Resolve (Days)'].mean().reset_index()

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=monthly_avg['Remediation Month'],
        y=monthly_avg['Time to Resolve (Days)'],
        mode='lines+markers',
        name='Average Time to Resolve',
        line=dict(color='#82c0ff', width=2)
    ))
    fig.update_layout(
        title=f'Average Time to Resolve Vulnerabilities by Month of Resolution ({severity_name})',
        xaxis_title='Month of Resolution',
        yaxis_title='Average Time to Resolve (Days)',
        showlegend=True,
        template='plotly_dark'
    )
    return fig.to_html(full_html=False, include_plotlyjs='cdn')


def create_remediation_line_chart(df_severity, severity_name):
    """
    Shows instance-level open vs. cumulative resolved counts over time.

    "Open in month M" = instances first detected in or before M that are currently
    open, plus instances that were resolved after M (meaning they were still open
    during M).  Uses Last Detected as the resolution proxy for Resolved rows.

    Tracking instances rather than unique CVEs is necessary because most remediation
    work partially reduces instances on a CVE without fully eliminating it, so a
    CVE-level chart would show almost no resolved activity.
    """
    if df_severity.empty:
        return None

    fd_periods = df_severity['First Detected (GMT -4)'].dt.to_period('M')
    ld_periods = df_severity['Last Detected (GMT -4)'].dt.to_period('M')
    is_open     = df_severity['Status'] == 'Open'
    is_resolved = df_severity['Status'] == 'Resolved'

    all_periods = pd.PeriodIndex(
        fd_periods.unique().tolist() + ld_periods[is_resolved].unique().tolist()
    ).unique().sort_values()

    if len(all_periods) == 0:
        return None

    chart_data = []
    for period in all_periods:
        fd_before = fd_periods <= period
        ld_after  = ld_periods > period   # resolved after this month → was still open during it

        open_count     = int((fd_before & (is_open | (is_resolved & ld_after))).sum())
        resolved_count = int((fd_before & is_resolved & (ld_periods <= period)).sum())

        chart_data.append({'Month': period.to_timestamp(), 'Open': open_count, 'Resolved': resolved_count})

    monthly_status_df = pd.DataFrame(chart_data).sort_values(by='Month')

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=monthly_status_df['Month'],
        y=monthly_status_df['Open'],
        mode='lines+markers',
        name='Open Vulnerabilities',
        line=dict(color='#ffcc00')
    ))
    fig.add_trace(go.Scatter(
        x=monthly_status_df['Month'],
        y=monthly_status_df['Resolved'],
        mode='lines+markers',
        name='Resolved Vulnerabilities',
        line=dict(color='#00cc66')
    ))
    fig.update_layout(
        title=f'Remediation Status Over Time ({severity_name})',
        xaxis_title='Month',
        yaxis_title='Number of Vulnerabilities',
        showlegend=True,
        template='plotly_dark'
    )
    return fig.to_html(full_html=False, include_plotlyjs='cdn')


def create_new_vulnerabilities_line_chart(cve_df_severity, severity_name):
    if cve_df_severity.empty:
        return None

    df_chart = cve_df_severity.copy()
    df_chart['First Detected Month'] = df_chart['earliest_first_detected'].dt.to_period('M').dt.to_timestamp()
    monthly_new = df_chart.groupby('First Detected Month')['Vulnerability CVE UID'].nunique().reset_index(name='New Vulnerabilities')

    fig = go.Figure(data=go.Scatter(
        x=monthly_new['First Detected Month'],
        y=monthly_new['New Vulnerabilities'],
        mode='lines+markers',
        name='New Vulnerabilities',
        line=dict(color='#b19cd9')
    ))
    fig.update_layout(
        title=f'New CVEs Found by Month ({severity_name})',
        xaxis_title='Month',
        yaxis_title='Number of New CVEs',
        showlegend=True,
        template='plotly_dark'
    )
    return fig.to_html(full_html=False, include_plotlyjs='cdn')


def normalize_device_name(name):
    if not name or not isinstance(name, str):
        return name
    return name.split('.')[0].strip()


def generate_device_list_content(cve_uid, device_names):
    return "\n".join(device_names)


def _collect_open_device_names(df_severity, cve_uid):
    """Returns deduplicated, normalized device names for open instances of a CVE."""
    device_names = []
    cve_rows = df_severity[
        (df_severity['Vulnerability CVE UID'] == cve_uid) &
        (df_severity['Status'] == 'Open')
    ]['Device Names']
    for names_list in cve_rows:
        device_names.extend([normalize_device_name(n) for n in names_list])
    return list(set(device_names))


def get_new_cves_this_month(df_severity, cve_df, reporting_date=None):
    if df_severity.empty:
        return []

    current_period = (reporting_date or pd.Timestamp.now()).to_period('M')
    new_cves = cve_df[
        (cve_df['earliest_first_detected'].dt.to_period('M') == current_period) &
        (cve_df['open_instances'] > 0)
    ].copy()

    results = []
    for _, row in new_cves.iterrows():
        cve_uid = row['Vulnerability CVE UID']
        device_names = _collect_open_device_names(df_severity, cve_uid)
        results.append({
            'cve_uid': cve_uid,
            'affected_devices_count': row['open_instances'],
            'cve_age_days': row['CVE_Age_Days'],
            'device_list_content': generate_device_list_content(cve_uid, device_names),
            'remediation_recommendation': row['Vulnerability Recommended Steps'].replace('<', '&lt;').replace('>', '&gt;')
        })
    return results


def get_top_cves(df_severity, cve_df):
    """Top 10 open CVEs by affected device count, excluding new-this-month CVEs."""
    if df_severity.empty:
        return []

    open_cves = cve_df[cve_df['open_instances'] > 0].sort_values('open_instances', ascending=False).head(10)

    results = []
    for _, row in open_cves.iterrows():
        cve_uid = row['Vulnerability CVE UID']
        device_names = _collect_open_device_names(df_severity, cve_uid)
        results.append({
            'cve_uid': cve_uid,
            'affected_devices_count': row['open_instances'],
            'cve_age_days': row['CVE_Age_Days'],
            'device_list_content': generate_device_list_content(cve_uid, device_names),
            'remediation_recommendation': row['Vulnerability Recommended Steps'].replace('<', '&lt;').replace('>', '&gt;')
        })
    return results


def get_oldest_cves(df_severity, cve_df):
    """10 oldest currently-open CVEs by age."""
    if df_severity.empty:
        return []

    open_cves = cve_df[cve_df['open_instances'] > 0].sort_values('CVE_Age_Days', ascending=False).head(10)

    results = []
    for _, row in open_cves.iterrows():
        cve_uid = row['Vulnerability CVE UID']
        device_names = _collect_open_device_names(df_severity, cve_uid)
        results.append({
            'cve_uid': cve_uid,
            'affected_devices_count': row['open_instances'],
            'cve_age_days': row['CVE_Age_Days'],
            'device_list_content': generate_device_list_content(cve_uid, device_names),
            'remediation_recommendation': row['Vulnerability Recommended Steps'].replace('<', '&lt;').replace('>', '&gt;')
        })
    return results


def calculate_vulnerability_statistics(cve_df_severity):
    """
    Stats for the summary cards. distinct_cves counts only CVEs with open instances
    so it matches what's actionable for the team.
    """
    stats = {
        'distinct_cves': 0,
        'open_instances': 0,
        'longest_open_cve_age': 0,
        'remediated_instances': 0
    }
    if cve_df_severity.empty:
        return stats

    open_cves = cve_df_severity[cve_df_severity['open_instances'] > 0]

    stats['distinct_cves'] = open_cves['Vulnerability CVE UID'].nunique()
    stats['open_instances'] = int(cve_df_severity['open_instances'].sum())
    stats['remediated_instances'] = int(cve_df_severity['remediated_instances'].sum())
    stats['longest_open_cve_age'] = int(open_cves['CVE_Age_Days'].max()) if not open_cves.empty else 0

    return stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate vulnerability reports from an enriched Armis CSV.")
    parser.add_argument("csv_file", nargs="?", default="report_Enriched.csv",
                        help="Path to the enriched CSV (default: report_Enriched.csv)")
    parser.add_argument("-d", "--date", metavar="YYYY-MM-DD",
                        help="Reporting date for age calculations and 'new this month' logic "
                             "(default: today). Use this to regenerate historical reports accurately.")
    args = parser.parse_args()

    reporting_date = pd.Timestamp(args.date) if args.date else None

    csv_file = args.csv_file
    all_data, _ = load_and_preprocess_data(csv_file, reporting_date)

    if all_data is None:
        print("Failed to load data, stopping report generation.")
    else:
        print("Data loading and preprocessing complete.")

        # (label, boundary filter, division)
        reports_config = [
            ("OIT Desktop",        "Desktop Team",        "OIT"),
            ("CID Desktop",        "Desktop Team",        "CID"),
            ("RL Desktop",         "Desktop Team",        "RL"),
            ("OIT Infrastructure", "Infrastructure Team", "OIT"),
            ("RL Infrastructure",  "Infrastructure Team", "RL"),
            ("OIT Mobile Devices", "Mobile Devices Team", "OIT"),
            ("OIT Network",        "Network Team",        "OIT"),
        ]

        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('report_template.html')

        output_reports_dir = "vulnerability_reports"
        os.makedirs(output_reports_dir, exist_ok=True)

        for label, boundary, division in reports_config:
            team_data = filter_data_by_team(all_data, boundary, division)
            if team_data.empty:
                print(f"\nNo data found for {label}. Skipping.")
                continue

            severity_grouped = group_data_by_severity(team_data)
            team_reports_data = {}

            for severity, df_severity in severity_grouped.items():
                if df_severity.empty:
                    continue

                print(f"\n--- Generating charts and tables for {label} - {severity} ---")

                cve_df = aggregate_cve_data(df_severity, reporting_date)

                new_cves_this_month = get_new_cves_this_month(df_severity, cve_df, reporting_date)
                new_cve_uids = {cve['cve_uid'] for cve in new_cves_this_month}
                cve_df_for_top10 = cve_df[~cve_df['Vulnerability CVE UID'].isin(new_cve_uids)].copy()

                team_reports_data[severity] = {
                    'severity_stats':                     calculate_vulnerability_statistics(cve_df),
                    'average_open_vulnerability_age_chart': create_average_open_vulnerability_age_chart(cve_df, severity),
                    'average_time_to_resolve_chart':      create_average_time_to_resolve_chart(cve_df, severity),
                    'remediation_chart':                  create_remediation_line_chart(df_severity, severity),
                    'new_vuln_chart':                     create_new_vulnerabilities_line_chart(cve_df, severity),
                    'new_cves_this_month':                new_cves_this_month,
                    'top_cves':                           get_top_cves(df_severity, cve_df_for_top10),
                    'oldest_cves':                        get_oldest_cves(df_severity, cve_df),
                }

            report_html = template.render(team_name=label, reports_data=team_reports_data)
            report_path = os.path.join(output_reports_dir, f"{label.replace(' ', '_')}_report.html")
            with open(report_path, 'w') as f:
                f.write(report_html)
            print(f"Generated report for {label} at {report_path}")

        print("\n--- All Reports Generated ---")
        print(f"Reports are located in the '{output_reports_dir}' directory.")
