### USE .env file
Put MSRC_KEY on .env file
.env
	MSRC_KEY=key_form_msrc_portal

Export env from .env file
	export $(cat .env | xargs)
