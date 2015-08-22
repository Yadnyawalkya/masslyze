from subprocess import call
import xml.etree.ElementTree as etree
from functions import vulnerability_checks
from functions import helper_functions
from functions import output_generation
import sys

# folgende Schachstellen bedacht:
# * certificate sachen nur im leaf certificate
# sslv3, sslv2, CRIME, heartbleed, client-init. reneg, certificate (hostname, trust, keysize, date,
# weak public key signature algorithm), rc4, weak/medium cipher
#
# fehlt: renego-isSecure

# TODO:
# *remove commandline output from the scan call


def execute_scan(target_file):
    scan_query = "sslyze-0_11-windows\sslyze.exe --regular --targets_in " + target_file + " --xml_out ergebnis.xml --timeout=10 --quiet"
    call(scan_query, shell=False, stdout=None, stderr=None)


def parse_xml(xml_file):
    # init the database
    helper_functions.cleanup_temp_files_u_db()
    db_cursor, db_connection = helper_functions.init_new_db()
    # read/parse the xml file
    tree = etree.parse(xml_file)
    root = tree.getroot()
    # check for invalid targets
    for child in root:
        if child.tag == "invalidTargets":
            invalid_targets = child
            invalid_targets = invalid_targets.findall('invalidTarget')
            for invalid_target in invalid_targets:
                db_cursor.execute('''INSERT INTO invalidtargets(name) VALUES (?)''', (invalid_target.text,))
                db_connection.commit()
        if child.tag == "results":
            results = child
    # for each valid host ...
    for target in results.findall('target'):
        host_ip = target.get('ip')
        host_name = target.get('host')
        host_port = target.get('port')
        db_cursor.execute('''INSERT INTO hosts(ip, hostname, port, info) VALUES (?, ?, ?, ?) ''', (host_ip, host_name, host_port, ''))
        db_connection.commit()
        # ... check every possible vulnerability
        try:
            for vulnerability in target:
                # sslv3 supported
                if vulnerability.tag == "sslv3":
                    vulnerability_checks.check_for_sslv3(db_cursor, host_ip, host_port, vulnerability)
                # sslv2 supported
                if vulnerability.tag == "sslv2":
                    vulnerability_checks.check_for_sslv2(db_cursor, host_ip, host_port, vulnerability)
                # CRIME (compression)
                if vulnerability.tag == "compression":
                    vulnerability_checks.check_for_crime(db_cursor, host_ip, host_port, vulnerability)
                # heartbleed
                if vulnerability.tag == "heartbleed":
                    vulnerability_checks.check_for_heartbleed(db_cursor, host_ip, host_port, vulnerability)
                # reneg
                if vulnerability.tag == "reneg":
                    vulnerability_checks.check_for_reneg(db_cursor, host_ip, host_port, vulnerability)
                # certificate
                if vulnerability.tag == "certinfo":
                    vulnerability_checks.check_for_certificate(db_cursor, host_ip, host_port, vulnerability)
                #  weak/medium keysize cipher support
                if vulnerability.tag == "sslv3" or "tlsv1" or "tlsv1_1" or "tlsv1_2":
                    vulnerability_checks.check_for_weakmedium_cipher_keysize(db_cursor, host_ip, host_port, vulnerability)
                # rc4 supported
                if vulnerability.tag == "sslv3" or "tlsv1" or "tlsv1_1" or "tlsv1_2":
                    vulnerability_checks.check_for_rc4_support(db_cursor, host_ip, host_port, vulnerability)
                db_connection.commit()
        except:
            db_connection.rollback()
            db_cursor.execute('''UPDATE hosts SET certificate=? WHERE ip=? AND port=?''', ('', host_ip, host_port))
            db_cursor.execute('''UPDATE hosts SET info=? WHERE ip=? AND port=?''', ("Error while parsing XML of this host. Use the following command to manually scan and analyse the host: sslyze --regular "+host_ip+":"+host_port, host_ip, host_port))
            db_connection.commit()
    db_connection.close()


def generate_outputfile():
    db_cursor, db_connection = helper_functions.connect_to_db()
    with open('output.txt', 'w') as outputfile:
        outputfile.write("Vulnerabilities sorted by Vulnerabilities:\n\n")
        output_generation.generate_output_by_vulns(db_cursor, outputfile)

        output_generation.attach_invalidtargets_to_output(db_cursor, outputfile)
    db_connection.close()


if __name__ == "__main__":

    if len(sys.argv) == 0:
        helper_functions.print_help()
    elif len(sys.argv) == 3 and sys.argv[1] == "-a":
        parse_xml(sys.argv[2])
        generate_outputfile()
        print("Done. Result in: output.txt")
    elif len(sys.argv) == 3 and sys.argv[1] == "-sa":
        print("The scan may take some time, be patient. Scanning...")
        execute_scan(sys.argv[2])
        parse_xml('ergebnis.xml')
        generate_outputfile()
        print("Done. Result in: output.txt")
    else:
        helper_functions.print_help()
