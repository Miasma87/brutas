#!/usr/bin/python

import subprocess
import os
import sys
import re

dest = os.path.abspath(sys.argv[1])
folder = "results/"
bar = "#################"

cmdDictionary = {'ipAddress': 'grep -sonrHaE \"\\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b\"',
                 'rsaPubKey': 'grep -snrHaE  "AAAA[0-9A-Za-z+/]+[=]{0,3} ([^@]+@[^@]+)"',
                 'rsaPriKey': '/* | sed -n -e \'/-----BEGIN RSA PRIVATE KEY-----/,/-----END RSA PRIVATE KEY-----/ p\'',
                 'certiDump': '/* | sed -n -e \'/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/ p\'',
                 'searWords': ' -rHna',
                 'urlSearch': 'grep -sonrHaE \'\\b(https?|ftp|file|http)://[a-zA-Z.-]*/[a-zA-Z0-9+-]*/[a-zA-Z0-9.,-+]*\'',
                 'pathSearc': 'grep -sonrHaE \'^[^/]*/[^/]*/[^/]*/[^_]*$\'',
                 'passSearc': 'grep -sonrHaE \'\$1\$...............................\''
                }

wordList = ['backdoor',
            'key',
            'pass',
            'root',
            'admin',
            'rood',
            'passwd',
            'username',
            'account',
            'acount'
            ]


def run_command(command):
    p = subprocess.Popen(command,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, shell=True)
    return iter(p.stdout.readline, b'')


def listCount(listToCount):
    return len(list(set(listToCount))) - 1


def extractIP():
    outputfile = open(folder + "ipfound.txt", 'w+')
    ipAddressList = ['']
    previousFilename = ""
    tempList = ['']

    print "Searching for IP",

    cmd = cmdDictionary['ipAddress'] + " " + dest
    for ip in run_command(cmd):
        filename = ip.split(dest)[-1][0:ip.split(dest)[-1].find(':')]
        if previousFilename != filename:
            print filename
            ipAddressList.append(filename)
            ipAddressList.extend(list(set(tempList)))
        #print ip.split(':', 2)[-1]
        ip = re.sub(':.*?:', ":", ip)
        tempList.append(ip.split(':', 2)[-1])
        #print ip.split(dest)[-1][0:ip.split(dest)[-1].find(':')]
        previousFilename = filename

    outputfile.write("".join(ipAddressList))
    print "\t-->Found " + str(listCount(ipAddressList)) + " strings that look like IP address"


def extractRSAPublicKeys():
    outputfile = open(folder + "rsaPubKeys.txt", 'w+')
    RSAPublicKeys = ['']

    print "Searching for RSA public Keys",

    cmd = cmdDictionary['rsaPubKey'] + " " + dest
    for pubKeys in run_command(cmd):
        #print pubKeys
        RSAPublicKeys.append(pubKeys.split(':', 2)[-1])

    outputfile.write("".join(RSAPublicKeys))
    print "\t-->Found " + str(listCount(RSAPublicKeys)) + " RSA public key(s)"


def extractRSAPrivateKeys():
    outputfile = open(folder + "rsaPriKeys.txt", 'w+')
    RSAPrivateKeys = ['']

    print "Searching for RSA private Keys",

    cmd = "strings 2>/dev/null " + dest + cmdDictionary['rsaPriKey']
    for priKey in run_command(cmd):
        #print priKey
        RSAPrivateKeys.append(priKey)

    outputfile.write("".join(RSAPrivateKeys))
    nbRSAPrivateKeys = RSAPrivateKeys.count('-----BEGIN RSA PRIVATE KEY-----\n')
    print "\t-->Found " + str(nbRSAPrivateKeys) + " RSA private key(s)"


def extractCertificates():
    outputfile = open(folder + "certificates.txt", 'w+')
    certificates = ['']

    print "Searching for certificates",

    cmd = "strings 2>/dev/null " + dest + cmdDictionary['certiDump']
    for cert in run_command(cmd):
        #print cert
        certificates.append(cert)

    outputfile.write("".join(certificates))
    #print certificates
    nbCertificates = certificates.count('-----BEGIN CERTIFICATE-----\n')
    print "\t-->Found " + str(nbCertificates) + " certificates"


def dictionaryFlawResearch():
    print "Searching for security related words"

    for word in wordList:
        outputfile = open(folder + word + "result.txt", 'w+')
        listOfWord = ['']

        cmd = "grep 2>/dev/null " + word + " " + dest + cmdDictionary['searWords']
        print "Testing keyword: " + word + "",
        for words in run_command(cmd):
            #print words
            listOfWord.append(words.split(':', 2)[-1])

        outputfile.write("\n".join(listOfWord))
        print "\t-->Found " + str(listCount(listOfWord)) + " times word " + word


def extractURL():
    outputfile = open(folder + "urls.txt", 'w+')
    urls = ['']

    print "Searching for URL",

    cmd = cmdDictionary['urlSearch'] + " " + dest
    #print cmd
    for url in run_command(cmd):
        #print url
        urls.append(url.split(':', 2)[-1])

    outputfile.write("".join(list(set(urls))))
    #print urls
    print "\t-->Found " + str(listCount(urls)) + " URL"


def extractPath():
    outputfile = open(folder + "paths.txt", 'w+')
    paths = ['']

    print "Searching for UNIX paths",

    cmd = cmdDictionary['pathSearc'] + " " + dest
    #print cmd
    for path in run_command(cmd):
        #print path
        paths.append(path.split(':', 2)[-1])

    outputfile.write("".join(list(set(paths))))
    #print paths
    print "\t-->Found " + str(listCount(paths)) + " \"Look-a-Like\" UNIX paths"
    print "You can use them with bruteLinks.py"


def extractPasswd():
    outputfile = open(folder + "passwd.txt", 'w+')
    passwds = ['']

    print "Searching for UNIX passwords",

    cmd = cmdDictionary['passSearc'] + " " + dest
    #print cmd
    for passwd in run_command(cmd):
        print passwd
        passwds.append(passwd.split(':', 2)[-1])

    outputfile.write("".join(list(set(passwds))))
    #print passwds
    print "\t-->Found " + str(listCount(passwds)) + " \"Look-a-Like\" UNIX passwords"


def main():
    if not os.path.exists(folder):
        os.makedirs(folder)
    print bar
    extractIP()
    print bar
    extractRSAPublicKeys()
    print bar
    extractRSAPrivateKeys()
    print bar
    extractCertificates()
    print bar
    dictionaryFlawResearch()
    print bar
    extractURL()
    print bar
    extractPath()
    print bar
    extractPasswd()
    print bar


main()
