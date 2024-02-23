import sys
import argparse
import requests

from bs4 import BeautifulSoup

_exit = sys.exit


def exit(message=None):
    if message:
        print("%s%s" % (message, ' ' * 20))
    _exit(1)


def parse_args():
    global args

    parser = argparse.ArgumentParser()
    parser.add_argument('CVE', type=str, nargs='*', default=[],
                        help='CVE in console (optional)')
    parser.add_argument('-f', '--file', type=str, help='If you want to insert CVE from .txt file, type filepath here')
    parser.add_argument('-o', '--output', type=str,
                        help='If you want to save the output to .txt file, type filepath here')
    args = parser.parse_args()


def cve_in_txt(input_path):
    if input_path:
        with open(input_path, 'r') as input_file:
            args.CVE += list(i.strip() for i in input_file.readlines())


def saving_output(output_path, output):
    if output_path is not None:
        with open(output_path, 'w') as output_file:
            output_file.writelines(output)
        print(f"Output saved to {args.output}")


def extract_vulnerability_data(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    description = soup.find('p', {'data-testid': 'vuln-description'}).text.strip()
    date = soup.find('span', {'data-testid': 'vuln-published-on'}).text.strip()
    cvss_v3_html = soup.find('input', {'id': 'nistV3MetricHidden'})['value']
    soup_cvss_v3 = BeautifulSoup(cvss_v3_html, 'html.parser')
    cvss_data = extract_cvss_data(soup_cvss_v3)
    return {
        'description': description,
        'date': date,
        'cvss': cvss_data
    }


def extract_cvss_data(cvss_v3):
    cvss_data = {}
    cvss_data[
        'base_score'] = f"{cvss_v3.find('span', {'data-testid': 'vuln-cvssv3-base-score'}).text.strip()} {cvss_v3.find('span', {'data-testid': 'vuln-cvssv3-base-score-severity'}).text.strip()}"
    cvss_data['vector'] = cvss_v3.find('span', {'data-testid': 'vuln-cvssv3-vector'}).text.strip()
    cvss_data['attack_vector'] = cvss_v3.find('span', {'data-testid': 'vuln-cvssv3-av'}).text.strip()
    cvss_data['attack_complexity'] = cvss_v3.find('span', {'data-testid': 'vuln-cvssv3-ac'}).text.strip()
    cvss_data['privileges_required'] = cvss_v3.find('span', {'data-testid': 'vuln-cvssv3-pr'}).text.strip()
    cvss_data['user_interaction'] = cvss_v3.find('span', {'data-testid': 'vuln-cvssv3-ui'}).text.strip()
    cvss_data['scope'] = cvss_v3.find('span', {'data-testid': 'vuln-cvssv3-s'}).text.strip()
    cvss_data['confidentiality'] = cvss_v3.find('span', {'data-testid': 'vuln-cvssv3-c'}).text.strip()
    cvss_data['integrity'] = cvss_v3.find('span', {'data-testid': 'vuln-cvssv3-i'}).text.strip()
    cvss_data['availability'] = cvss_v3.find('span', {'data-testid': 'vuln-cvssv3-a'}).text.strip()
    return cvss_data


def run():
    output = list()
    for cve_name in args.CVE:
        url = 'https://nvd.nist.gov/vuln/detail/' + cve_name
        response = requests.get(url)
        if response.status_code == 200:
            html_content = response.content
            vulnerability_data = extract_vulnerability_data(response.content)
            cvss = vulnerability_data['cvss']
            cve_information = (f"{'_' * 30}\n"
                               f"Name: {cve_name}\n"
                               f"Date: {vulnerability_data['date']}\n"
                               f"Link: {url}\n"
                               f"Description: {vulnerability_data['description']}\n"
                               f"CVSS v3.0 Base Score: {cvss['base_score']}\n"
                               f"CVSS Vector: {cvss['vector']}\n"
                               f"Attack Vector: {cvss['attack_vector']}\n"
                               f"Attack Complexity: {cvss['attack_complexity']}\n"
                               f"Privileges Required: {cvss['privileges_required']}\n"
                               f"User interaction: {cvss['user_interaction']}\n"
                               f"Scope: {cvss['scope']}\n"
                               f"Confidentiality: {cvss['confidentiality']}\n"
                               f"Integrity: {cvss['integrity']}\n"
                               f"Availability: {cvss['availability']}\n"
                               f"{'_' * 30}\n")
            print(cve_information)
            output.append(cve_information)
        else:
            print("Error:", response.status_code)
    print(f"Done! {len(args.CVE)} CVE processed.")
    return output


def main():
    parse_args()
    cve_in_txt(args.file)
    output = run()
    saving_output(args.output, output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit("\r[x] Ctrl-C pressed")
