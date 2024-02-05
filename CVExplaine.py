import sys
import argparse
import json
import requests

from googletrans import Translator

_exit = sys.exit


def exit(message=None):
    if message:
        print("%s%s" % (message, ' ' * 20))
    _exit(1)


def parse_args():
    global args

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', type=str, help='Insert filepath to .txt file with CVE names here (Required)',
                        required=True)  # обязательный параметр
    parser.add_argument('-o', '--output', type=str,
                        help='If you want to save the output to .txt file, insert filepath here')
    parser.add_argument('-t', '--translate', action='store_true', help='Enables translate')
    args = parser.parse_args()


def start(input_path):
    with open(input_path, 'r') as input_file:
        cve_names = list(i.strip() for i in input_file.readlines())
        return cve_names


def translate(text):
    translator = Translator()
    translated_text = (translator.translate(text, dest='ru')).text.strip()
    return translated_text


def saving_output(output_path, output):
    with open(output_path, 'w') as output_file:
        output_file.writelines(output)


def run():
    result = []
    cve_names = start(args.file)
    for cve_name in cve_names:
        response = requests.get("https://cve.circl.lu/api/cve/" + cve_name)
        if response.status_code == 200:
            data = json.loads(response.text)
            description = data["summary"]
            date = data["Published"][:10]
            information = (f"Name: {cve_name}\n"
                           f"Date: {date}\n"
                           f"Link: {'https://cve.circl.lu/api/cve/' + cve_name}\n"
                           f"Description: {description}\n")
            if args.translate:
                translation = translate(description)
                information += f"Translated: {translation}\n"

            if data["cvss"] is not None:
                cvss_score = data["cvss"]
                cvss_vector = data["cvss-vector"]
                authentication = data["access"]["authentication"]
                complexity = data["access"]["complexity"]
                attack_vector = data["access"]["vector"]
                information += (f"CVSS 2.0 Base Score: {cvss_score}\n"
                                f"VSS Vector: {cvss_vector}\n"
                                f"Authentication: {authentication}\n"
                                f"Complexity: {complexity}\n"
                                f"Vector = {attack_vector}\n")
            else:
                information += f"No CVSS found\n"
            information += "\n"
            result.append(information)
            print(information)
        else:
            print(f"ERROR while receiving file. Status code: {response.status_code}, {cve_name}")

    if args.output is not None:
        saving_output(args.output, result)
        print(f"Output saved to {args.output}")

    print("DONE!")


def main():
    parse_args()
    run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit("\r[x] Ctrl-C pressed")
