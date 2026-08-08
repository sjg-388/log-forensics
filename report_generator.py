import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

def get_env():
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
    return Environment(loader=FileSystemLoader(template_dir))

def build_context(log_file, total_events, all_findings, ioc, timeline,
                  ua_findings, bf_findings, ds_findings, sqli_findings):
    return {
        "log_file": os.path.basename(log_file),
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_events": total_events,
        "total_findings": len(all_findings),
        "ioc": ioc,
        "timeline": timeline,
        "ua_count": len(ua_findings),
        "bf_count": len(bf_findings),
        "ds_count": len(ds_findings),
        "sqli_count": len(sqli_findings),
    }

def generate_markdown_report(log_file, total_events, all_findings, ioc, timeline,
                              ua_findings, bf_findings, ds_findings, sqli_findings):
    env = get_env()
    template = env.get_template("report.md.j2")
    context = build_context(log_file, total_events, all_findings, ioc, timeline,
                            ua_findings, bf_findings, ds_findings, sqli_findings)
    report = template.render(context)
    
    base = os.path.splitext(os.path.basename(log_file))[0]
    report_path = f"{base}_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"Markdown 리포트 저장 완료: {report_path}")
    return report_path

def generate_html_report(log_file, total_events, all_findings, ioc, timeline,
                         ua_findings, bf_findings, ds_findings, sqli_findings):
    env = get_env()
    template = env.get_template("report.html.j2")
    context = build_context(log_file, total_events, all_findings, ioc, timeline,
                            ua_findings, bf_findings, ds_findings, sqli_findings)
    report = template.render(context)
    
    base = os.path.splitext(os.path.basename(log_file))[0]
    report_path = f"{base}_report.html"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"HTML 리포트 저장 완료: {report_path}")
    return report_path