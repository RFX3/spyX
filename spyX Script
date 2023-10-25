import os
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import urllib.parse
import builtwith
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image
from datetime import datetime
from reportlab.platypus import PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import dns.resolver
import whois
import pyfiglet
import subprocess

#Create the SPYX title with blue color 
title = pyfiglet.figlet_format('SPYX', font='slant')
blue_title = f'\033[34m{title}\033[0m'  # \033[34m sets the text color to blue, \033[0m resets it

#Print the title
print(blue_title)

# Function to fetch and format the contents of robots.txt in a table
def format_robots_txt(target_domain):
    robots_url = f"http://{target_domain}/robots.txt"
    paths_and_permissions = []

    try:
        response = requests.get(robots_url)
        if response.status_code == 200:
            robots_txt = response.text
            for line in robots_txt.split('\n'):
                line = line.strip()
                if line.startswith("Disallow:") or line.startswith("Allow:"):
                    parts = line.split()
                    if len(parts) == 2:
                        path = parts[1]
                        permission = parts[0].rstrip(':')
                        paths_and_permissions.append([path, permission])

        return paths_and_permissions

    except Exception:
        return [["Error fetching robots.txt", ""]]

# Function to save results to a PDF report
def save_results_to_pdf(output_dir, target_domain, subdomains, parameters, nameservers, robots_txt, directories, whois_info):
    pdf_file = os.path.join(output_dir, "recon_results.pdf")

    doc = SimpleDocTemplate(pdf_file, pagesize=letter)
    story = []

    # Report Title
    styles = getSampleStyleSheet()
    title = "Reconnaissance Report"
    title_style = styles["Title"]
    title_text = Paragraph(title, title_style)
    story.append(title_text)
    story.append(Spacer(1, 12))

    # Insert the image on page 1
    #image_path = "C:\\Downloads\\spyX.png"  # Replace with the actual path to the image
    #image = Image(image_path, width=550, height=550)
    #story.append(image)

    # Target Domain
    target_domain_style = ParagraphStyle(name="TargetDomain", parent=styles["Normal"])
    target_domain_style.fontName = "Helvetica"
    story.append(Paragraph(f"Target Domain: {target_domain}", target_domain_style))
    story.append(Spacer(1, 12))

    # Add the date under the image
    now = datetime.now()
    current_date = now.strftime("%Y-%m-%d %H:%M:%S")
    story.append(Paragraph(f"Report Date: {current_date}", target_domain_style))
    story.append(PageBreak())

    # Subdomains
    subdomains_data = [["Subdomain"]]
    for subdomain in subdomains:
        subdomains_data.append([subdomain])
    subdomains_table = Table(subdomains_data, colWidths=[4 * inch])
    subdomains_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(Paragraph("Subdomains:", styles["Normal"]))
    story.append(subdomains_table)
    story.append(Spacer(1, 12))

    # Parameters
    params_data = [["Parameter"]]
    for param in parameters:
        params_data.append([param])
    params_table = Table(params_data, colWidths=[4 * inch])
    params_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(Paragraph("Parameters:", styles["Normal"]))
    story.append(params_table)
    story.append(Spacer(1, 12))

    # Nameservers
    nameservers_data = [["Nameserver"]]
    for nameserver in nameservers:
        nameservers_data.append([nameserver])
    nameservers_table = Table(nameservers_data, colWidths=[4 * inch])
    nameservers_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(Paragraph("Nameservers:", styles["Normal"]))
    story.append(nameservers_table)
    story.append(Spacer(1, 12))

    # Directories
    dir_data = [["Directory"]]
    for directory in directories:
        dir_data.append([directory])
    dir_table = Table(dir_data, colWidths=[4 * inch])
    dir_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(Paragraph("Directories:", styles["Normal"]))
    story.append(dir_table)
    story.append(Spacer(1, 12))

    # Robots.txt Content
    if robots_txt:
        robots_txt_data = [["Path", "Permission"]]
        for path, permission in robots_txt:
            robots_txt_data.append([path, permission])
        robots_txt_table = Table(robots_txt_data, colWidths=[3.5 * inch, 1 * inch])
        robots_txt_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(Paragraph(f"Robots.txt Content for {target_domain}:", styles["Normal"]))
        story.append(robots_txt_table)

    # WHOIS Information
    if whois_info:
        whois_data = [["WHOIS Field", "Value"]]
        for key, value in whois_info.items():
            value = str(value)
            value = value[:55]
            whois_data.append([key, str(value)])
        whois_table = Table(whois_data, colWidths=[3.5 * inch, 4.5 * inch])
        whois_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(Paragraph("WHOIS Information:", styles["Normal"]))
        story.append(whois_table)
        story.append(Spacer(1, 12))

    doc.build(story)

# Function to enumerate subdomains
def enumerate_subdomains(target_domain):
    subdomains = set()
    try:
        response = requests.get(f"http://{target_domain}")
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            for a_tag in soup.find_all('a'):
                href = a_tag.get('href')
                if href and target_domain in href:
                    subdomain = urlparse(href).netloc
                    subdomains.add(subdomain)
        # You can add more subdomain enumeration techniques here
    except Exception:
        pass
    return subdomains

# Function to enumerate directories
def enumerate_directories(target_url):
    directories = set()
    try:
        response = requests.get(target_url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and not href.startswith(('http://', 'https://', 'mailto:')):
                    full_url = urllib.parse.urljoin(target_url, href)
                    directories.add(full_url)
    except Exception:
        pass
    return directories

# Function to extract visible and hidden parameters from URLs
def extract_parameters(target_url):
    parameters = set()
    try:
        response = requests.get(target_url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                for input_elem in form.find_all('input'):
                    name = input_elem.get('name')
                    if name:
                        parameters.add(name)
            for input_elem in soup.find_all('input', type='hidden'):
                name = input_elem.get('name')
                if name:
                    parameters.add(name)
    except Exception:
        pass
    return parameters

# Function to detect web technologies used on the target website
def detect_web_technologies(target_url):
    technologies = builtwith.parse(target_url)
    return technologies

# Function to fetch and print the contents of PHPInfo
def print_phpinfo(target_domain):
    phpinfo_url = f"http://{target_domain}/phpinfo.php"
    try:
        response = requests.get(phpinfo_url)
        if response.status_code == 200:
            return response.text
        else:
            return "PHPInfo page not found."
    except Exception:
        return "Error checking PHPInfo page."

# Function to print nameservers of the target domain
def print_nameservers(target_domain):
    try:
        nameservers = set()
        answers = dns.resolver.resolve(target_domain, 'NS')
        for rdata in answers:
            nameservers.add(rdata.to_text())
        return list(nameservers)
    except:
        pass

# Function to get WHOIS information for the target domain
def get_whois_info(target_domain):
    try:
        result = whois.whois(target_domain)
        # Filter out the "emails" field from the WHOIS data
        if "emails" in result:
            del result["emails"]
        return result
    except Exception as e:
        return str(e)

# Function to open the generated PDF report
def open_pdf_report(pdf_file):
    try:
        if os.name == 'posix':  # For Unix-based systems like Linux and macOS
            subprocess.Popen(['xdg-open', pdf_file])
        elif os.name == 'nt':  # For Windows
            os.startfile(pdf_file)
    except Exception:
        print("Error opening the PDF report.")

# Main function
def main():
    target_domain = input("Enter the target domain (e.g., example.com): ")
    output_dir = f"{target_domain}_recon"
    os.makedirs(output_dir, exist_ok=True)

    # Subdomain Enumeration
    subdomains = enumerate_subdomains(target_domain)

    # Directory Enumeration
    target_url = f"http://{target_domain}"
    directories = enumerate_directories(target_url)

    # Parameter Discovery (Visible and Hidden)
    parameters = extract_parameters(target_url)

    # Web Technology Detection
    technologies = detect_web_technologies(target_url)

    # Additional functionalities
    robots_txt = format_robots_txt(target_domain)
    nameservers = print_nameservers(target_domain)
    whois_info = get_whois_info(target_domain)

    # Save results to a PDF report
    save_results_to_pdf(output_dir, target_domain, subdomains, parameters, nameservers, robots_txt, directories, whois_info)

    print(f"Recon results saved in {output_dir}/recon_results.pdf")

    # Open the generated PDF report
    open_pdf_report(os.path.join(output_dir, "recon_results.pdf"))

if __name__ == "__main__":
    main()
