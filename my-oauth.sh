#!/bin/bash

user="rafael.tinoco@canonical.com"
client_id="443898221810-83cel7n2npag017qicak24jf9v3o68rm.apps.googleusercontent.com"
client_secret="wpn-Ac-S_qdIru1jkMM_t82g"

oauth2.py \
    --user=$user \
    --client_id=$client_id \
    --client_secret=$client_secret \
    --generate_oauth2_token

# Enter verification code: 4/2AEMqe5KDAnFTsrouK-TDyolYpOI7mSJhX06vGd4qZ7Ucb4CqVOIoIM
# Refresh Token: 1//0huehX-BIgnBbCgYIARAAGBESNwF-L9Ir_qM99vjUmhckGVurbeTupUutGi3XwQJzo95zAPFjEGqiRt-Bvj4OLxoLdZFOYpVbHS8
# Access Token: ya29.a0AfH6SMBQFxyUrbYgBB5N4VtPdGcZZwFPp6WnXwFmruHVIf55EdX252EBcKEfr1q83WxuASU1BLZePpmWG-m5bFS7FK5nFVxXUZfu6v5eeRBIT-lK2pLLZiWDflVYRwPdgRRygosL0g8Z1JpvQrnLzMXibphQgUFeCeA
# Access Token Expiration Seconds: 3599
