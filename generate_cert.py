#!/usr/bin/env python

import argparse
from lxml import html
import requests
from OpenSSL import crypto
import logging as log
import random, string

START_URL="https://secure.comodo.com/products/frontpage?area=SecureEmailCertificate"
ORDER_URL="https://secure.comodo.com/products/!SecureEmailCertificate_Signup"


def load_key(privkey_file):
	log.info("Reading PEM formated private key from %s",privkey_file)
	with open(privkey_file, 'rb') as f:
		keydata = f.read()
	privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, keydata)
	log.info("Converting public key to SPKAC format")
	spkac=crypto.NetscapeSPKI()
	# Dump and parse the public key. not necessarry but double-ensures that we never put the private key to the SPKAC string
	pubkey = crypto.load_publickey(crypto.FILETYPE_PEM, crypto.dump_publickey(crypto.FILETYPE_PEM, privkey))
	spkac.set_pubkey(pubkey)
	log.info("Signing SPKAC key with private key")
	spkac.sign(privkey,'sha1')
	return spkac.b64_encode()

def get_entry_page():
	log.info("Fetching %s",START_URL)
	page=requests.get(START_URL)
	if not "Application for Secure Email Certificate" in page.content:
		raise Exception("Got unexpected page content")
	tree = html.fromstring(page.content)
	sid = tree.xpath('//input[@name="SID"]/@value')
	if not sid:
		raise Exception("Field SID not found!")
	country_options = tree.xpath('//select[@name="countryName"]/option')
	if not country_options:
		raise Exception("Selection-Field countryName not found!")
	countries={}
	for country_option in country_options:
		countries[country_option.text]=country_option.get('value')
	agreement_url = tree.xpath('//iframe/@src')
	if not agreement_url:
		raise Exception("Agreement iframe not found!")
	return (sid[0],countries,agreement_url[0])

def order_certificate(sid,firstname,lastname,email,country,password,spkac):
	log.info("Ordering certificate at %s",ORDER_URL)
	data={
		'SID':sid,
		'countryName':country,
		'foreName':firstname,
		'surname':lastname,
		'emailAddress': email,
		'challengePassword': password,
		'spkac': spkac,
		'iAccept':'on',
		'submitButton':'Next+'
		}
	page=requests.post(ORDER_URL,data)
	if not 'Application is successful' in page.content:
		raise Exception("Something went wrong. Page HTML is: %s",page.content)

def main():

	log.basicConfig(level=log.INFO)

	parser = argparse.ArgumentParser(description='Order a free S/MIME certificate from comodo (see %s)'%START_URL)
	parser.add_argument('--accept-agreement-url', dest='agreement_url', help='The URL of the agreement that you accept to get the certificate.')
	parser.add_argument('--country', help='Your country. Must be in the list at the order page.', required=True)
	parser.add_argument('--firstname', help='Your first name', required=True)
	parser.add_argument('--lastname', help='Your last name', required=True)
	parser.add_argument('--email', help='Your email address', required=True)
	parser.add_argument('--privkey', help='Private key file (PEM format)', required=True)
	parser.add_argument('--revoke-password', help='A password that can be used to revoke the certificate. If ommitted, a random password will be generated.')
	args = parser.parse_args()

	spkac=load_key(args.privkey)

	(sid,countries,agreement_url)=get_entry_page()
	if args.agreement_url != agreement_url:
		raise Exception("You need to accept the following agreement: %s" % agreement_url)

	if not args.country in countries:
		raise Exception("The country is not on the list of supported countries")

	if not args.revoke_password:
		rng = random.SystemRandom()
		args.revoke_password=''.join([ rng.choice(string.ascii_letters + string.digits) for _ in xrange(15) ])
		log.info("Please note the following password. It is requred to revoke your certificate: %s",args.revoke_password)

	order_certificate(sid,args.firstname,args.lastname,args.email,countries[args.country],args.revoke_password,spkac)

if __name__ == "__main__":
    main()