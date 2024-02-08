#!/bin/bash

# Array of URLs to check
URLS=("www.kibana-openshift-logging.apps.upiprod.finopaymentbank.in" "www.kiali-istio-system.apps.upiprod.finopaymentbank.in" "www.10.71.87.48:8080")
EXPIRED_THRESHOLD=0  # Number of days after expiration to trigger alert
ALERT_THRESHOLD=7	# Number of days before expiration to trigger alert
RECIPIENT_EMAIL="krish_01@fosteringlinux.com"
SENDER_EMAIL="vikas_dhumale@finobank.com"

# Function to send email alert
send_email_alert() {
	local subject=$1
	local body=$2
	echo -e "${body}" | mailx -s "${subject}" -r "${SENDER_EMAIL}" -S smtp="10.71.87.201:25" "${RECIPIENT_EMAIL}"
	echo "Email alert sent."
}

# Function to check SSL certificate for a given URL
check_ssl_certificate() {
	local SSL_HOSTNAME=$1
	local SSL_PORT=443

	cert_info=$(openssl s_client -showcerts -connect "${SSL_HOSTNAME}:${SSL_PORT}" </dev/null 2>/dev/null)

	if [[ $? -eq 0 ]]; then
    	expiration_date=$(echo "${cert_info}" | openssl x509 -noout -enddate | cut -d= -f2)
    	if [ -n "${expiration_date}" ]; then
        	expiration_epoch=$(date -d "${expiration_date}" +%s)
        	current_epoch=$(date +%s)
        	days_until_expiry=$(( (${expiration_epoch} - ${current_epoch}) / 86400 ))

        	if [ ${days_until_expiry} -gt ${EXPIRED_THRESHOLD} ]; then
            	echo "The SSL certificate for ${SSL_HOSTNAME} is valid for ${days_until_expiry} days."

            	if [ ${days_until_expiry} -le ${ALERT_THRESHOLD} ]; then
                	echo "Sending email alert for SSL certificate expiry..."
                	subject="SSL Certificate Expiry Alert for ${SSL_HOSTNAME}"
                	email_body="The SSL certificate for ${SSL_HOSTNAME} is about to expire in ${days_until_expiry} days. Please take appropriate action to renew the certificate."
                	send_email_alert "${subject}" "${email_body}"
            	fi

        	else
            	echo "The SSL certificate for ${SSL_HOSTNAME} has expired."
            	echo "Sending email alert for expired SSL certificate..."
            	subject="Expired SSL Certificate Alert for ${SSL_HOSTNAME}"
            	email_body="The SSL certificate for ${SSL_HOSTNAME} has expired. Please take immediate action to renew the certificate."
            	send_email_alert "${subject}" "${email_body}"
        	fi
    	else
        	echo "Error extracting expiration date from SSL certificate for ${SSL_HOSTNAME}."
        	echo "Sending email alert for expiration date extraction error..."
        	subject="SSL Certificate Expiry Alert Error for ${SSL_HOSTNAME}"
        	email_body="Error extracting expiration date from SSL certificate for ${SSL_HOSTNAME}. Please check the SSL configuration."
        	send_email_alert "${subject}" "${email_body}"
    	fi
	else
    	echo "Error connecting to the SSL endpoint for ${SSL_HOSTNAME}."
    	echo "Sending email alert for SSL connection error..."
    	subject="SSL Connection Error for ${SSL_HOSTNAME}"
    	email_body="Error connecting to the SSL endpoint for ${SSL_HOSTNAME}. Please check the SSL configuration and server availability."
    	send_email_alert "${subject}" "${email_body}"
	fi
}

# Loop through each URL and check SSL certificate
for URL in "${URLS[@]}"; do
	check_ssl_certificate "$URL"
done
