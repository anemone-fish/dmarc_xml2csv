import os
import glob
import csv
import sys
from datetime import datetime
from xml.etree import ElementTree

def process_xml(file):
    try:
        tree = ElementTree.parse(file)
        root = tree.getroot()

        report_metadata = root.find("report_metadata")
        org_name = report_metadata.findtext("org_name")
        email = report_metadata.findtext("email")
        report_id = report_metadata.findtext("report_id")
        date_range = report_metadata.find("date_range")
        begin = datetime.utcfromtimestamp(int(date_range.findtext("begin")))
        end = datetime.utcfromtimestamp(int(date_range.findtext("end")))

        records = []
        for record in root.findall("record"):
            row = record.find("row")
            source_ip = row.findtext("source_ip")
            count = row.findtext("count")
            policy_evaluated = row.find("policy_evaluated")
            disposition = policy_evaluated.findtext("disposition")
            spf_dmarc_result = policy_evaluated.findtext("spf")
            dkim_dmarc_result = policy_evaluated.findtext("dkim")

            identifiers = record.find("identifiers")
            header_from = identifiers.findtext("header_from")
            envelope_to = identifiers.findtext("envelope_to")

            auth_results = record.find("auth_results")
            dkim_tags = auth_results.findall("dkim")
            spf_tags = auth_results.findall("spf")

            for dkim_tag, spf_tag in zip(dkim_tags, spf_tags):
                dkim_domain = dkim_tag.findtext("domain")
                dkim_result = dkim_tag.findtext("result")
                spf_domain = spf_tag.findtext("domain")
                spf_result = spf_tag.findtext("result")

                dkim_alignment = "pass" if dkim_domain == header_from else "fail"
                spf_alignment = "pass" if spf_domain == header_from else "fail"

                records.append([source_ip, count, disposition, spf_dmarc_result, dkim_dmarc_result, header_from, envelope_to,
                                spf_result, spf_alignment, spf_domain, dkim_result, dkim_alignment, dkim_domain,
                                org_name, email, report_id, begin, end])

        return records

    except Exception as e:
        print(f"Error processing file {file}: {e}")
        return []

def main(xml_folder, output_file):
    csv_header = ["IP Address", "Count", "DMARC Disposition", "DMARC SPF", "DMARC DKIM", "Header-From", "Envelope-To",
                  "SPF Authentication", "SPF Alignment", "SPF Domain", "DKIM Authentication", "DKIM Alignment",
                  "DKIM Domain", "Org Name", "Email", "Report ID", "Begin Date", "End Date"]

    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(csv_header)

        for xml_file in glob.glob(os.path.join(xml_folder, "*.xml")):
            rows = process_xml(xml_file)
            csv_writer.writerows(rows)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python dmarc_xml2csv.py <xml_folder> <output_file>")
        sys.exit(1)

    xml_folder = sys.argv[1]
    output_file = sys.argv[2]
    main(xml_folder, output_file)
