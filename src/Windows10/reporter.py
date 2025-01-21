import pandas as pd
import plotly.express as px
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

class Reporter:
    def generate_report(self, vulnerabilities, file_path):
        if file_path.endswith(".pdf"):
            self._generate_pdf_report(vulnerabilities, file_path)
        elif file_path.endswith(".csv"):
            self._generate_csv_report(vulnerabilities, file_path)
        elif file_path.endswith(".html"):
            self._generate_html_report(vulnerabilities, file_path)

    def _generate_pdf_report(self, vulnerabilities, file_path):
        c = canvas.Canvas(file_path, pagesize=letter)
        c.drawString(100, 750, "WinVulnScan Report")
        y = 730
        for vulnerability in vulnerabilities:
            c.drawString(100, y, vulnerability)
            y -= 20
        c.save()

    def _generate_csv_report(self, vulnerabilities, file_path):
        df = pd.DataFrame(vulnerabilities, columns=["Vulnerability"])
        df.to_csv(file_path, index=False)

    def _generate_html_report(self, vulnerabilities, file_path):
        df = pd.DataFrame(vulnerabilities, columns=["Vulnerability"])
        fig = px.bar(df, x="Vulnerability", title="Vulnerability Report")
        fig.write_html(file_path)￼Enter
