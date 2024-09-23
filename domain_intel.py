import whois
import dns.resolver
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def whois_lookup(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        return f"Error retrieving WHOIS information: {e}"

def dns_records(domain):
    records = {}
    try:
        for record_type in ['A', 'AAAA', 'MX', 'TXT', 'CNAME']:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [answer.to_text() for answer in answers]
    except Exception as e:
        records['error'] = f"Error retrieving DNS records: {e}"
    return records

def ssl_tls_info(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                return {
                    "issuer": x509_cert.issuer.rfc4514_string(),
                    "subject": x509_cert.subject.rfc4514_string(),
                    "valid_from": x509_cert.not_valid_before,
                    "valid_to": x509_cert.not_valid_after,
                    "serial_number": x509_cert.serial_number,
                    "signature_algorithm": x509_cert.signature_algorithm_oid._name
                }
    except Exception as e:
        return f"Error retrieving SSL/TLS information: {e}"

def gather_domain_info(domain):
    domain_info = {}

    domain_info['whois'] = whois_lookup(domain)
    domain_info['dns_records'] = dns_records(domain)
    domain_info['ssl_tls'] = ssl_tls_info(domain)

    return domain_info

def print_domain_info(domain_info, text_area):
    text_area.delete(1.0, tk.END)

    # Define colors for highlighting
    whois_color = "blue"
    dns_color = "green"
    ssl_color = "red"

    # WHOIS Information
    whois_info = domain_info.get('whois', {})
    if isinstance(whois_info, dict):
        text_area.insert(tk.END, "WHOIS Information:\n\n", whois_color)
        for key, value in whois_info.items():
            if isinstance(value, list):
                value = ', '.join(map(str, value))
            text_area.insert(tk.END, f"{key}: {value}\n")
    else:
        text_area.insert(tk.END, f"WHOIS Information:\n{whois_info}\n", whois_color)

    text_area.insert(tk.END, "\n")

    # DNS Records
    dns_records = domain_info.get('dns_records', {})
    text_area.insert(tk.END, "DNS Records:\n\n", dns_color)
    for record_type, records in dns_records.items():
        if isinstance(records, list):
            records = ', '.join(map(str, records))
        text_area.insert(tk.END, f"{record_type}: {records}\n")

    text_area.insert(tk.END, "\n")

    # SSL/TLS Information
    ssl_info = domain_info.get('ssl_tls', {})
    text_area.insert(tk.END, "SSL/TLS Information:\n\n", ssl_color)
    for key, value in ssl_info.items():
        text_area.insert(tk.END, f"{key}: {value}\n")

def generate_report(domain_info, domain, filename):
    pdf_filename = f"{filename}.pdf"
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica", 14)
    c.drawString(30, height - 40, f"Domain Information Report for {domain}")
    c.setFont("Helvetica", 12)

    y_position = height - 70

    def draw_section(title, content):
        nonlocal y_position
        c.drawString(30, y_position, title)
        y_position -= 20
        if isinstance(content, dict):
            for key, value in content.items():
                c.drawString(50, y_position, f"{key}: {value}")
                y_position -= 15
        else:
            c.drawString(50, y_position, content)
            y_position -= 15
        y_position -= 10

    draw_section("WHOIS Information:", domain_info.get('whois', 'No data'))
    draw_section("DNS Records:", domain_info.get('dns_records', {}))
    draw_section("SSL/TLS Information:", domain_info.get('ssl_tls', {}))

    c.save()
    messagebox.showinfo("Report Generated", f"Report saved as {pdf_filename}")

def on_scan_click(entry, text_area, download_button):
    domain = entry.get()
    domain_info = gather_domain_info(domain)
    print_domain_info(domain_info, text_area)
    download_button.config(state=tk.NORMAL, command=lambda: download_report(domain_info, domain))

def download_report(domain_info, domain):
    filename = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")], title="Save PDF Report As")
    if filename:
        generate_report(domain_info, domain, filename)

def create_gui():
    root = tk.Tk()
    root.title("Domintel - Domain Information Gatherer")

    tk.Label(root, text="Domintel", font=("Arial", 20)).pack(pady=10)
    
    frame = tk.Frame(root)
    frame.pack(pady=10)

    tk.Label(frame, text="Enter Domain:", font=("Arial", 14)).pack(side=tk.LEFT)
    domain_entry = tk.Entry(frame, width=40, font=("Arial", 14))
    domain_entry.pack(side=tk.LEFT, padx=5)

    scan_button = tk.Button(root, text="Scan Domain", font=("Arial", 14), command=lambda: on_scan_click(domain_entry, result_text, download_button))
    scan_button.pack(pady=10)

    result_text = scrolledtext.ScrolledText(root, width=80, height=20, font=("Arial", 12))
    result_text.pack(pady=10)

    download_button = tk.Button(root, text="Download PDF Report", font=("Arial", 14), state=tk.DISABLED)
    download_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
