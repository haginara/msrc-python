Preparation
-----------
### Install requirements
	pip install requests

### USE .env file
Put MSRC_KEY on .env file
.env
	MSRC_KEY=key_form_msrc_portal

Export env from .env file
	export $(cat .env | xargs)

Usage
-----
	python msrc.py CVE-2018-8174
