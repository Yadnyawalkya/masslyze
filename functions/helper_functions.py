import os
import sqlite3


def cleanup_temp_files_u_db(DEBUG=False):
    if os.path.isfile('work.db'):
        os.remove('work.db')
    if DEBUG == False:
        if os.path.isfile('ergebnis.xml'):
            os.remove('ergebnis.xml')


def init_new_db():
    conn = sqlite3.connect('work.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE hosts (ip text, hostname text, port text, sslv3 boolean, sslv2 boolean, CRIME boolean, heartbleed boolean, reneg boolean, certificate text, weakmediumcipher boolean, rc4 boolean, info text) ''')
    conn.commit()
    c.execute('''CREATE TABLE invalidtargets (name text)''')
    conn.commit()
    return c, conn


def connect_to_db():
    conn = sqlite3.connect('work.db')
    c = conn.cursor()
    return c, conn


def print_help():
    print("*"*47 + "\n* MASSLYZE - Analyse multiple SSL/TLS servers *\n" + "*"*47)
    print("Help...\nMASSLYZE is a tool to analyse the XML output of sslyze.")
    print("You can either analyse a XML file created with sslyze, or do a scan with sslyze and analyse it directly.")
    print("Useage:")
    print("Analyse only:   $python masslyze.py -a path_to_XMLFILE_CREATED_WITH_SSLYZE")
    print("Scan + Analyse: $python masslyze.py -sa path_to_TXTFILE_WITH_TARGET_HOSTS:PORT_EACH_IN_NEW_LINE")
    print("Output in: output.txt")
