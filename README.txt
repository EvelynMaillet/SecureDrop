SecureDrop

    This is a more secure implementation of Airdrop. It uses the following technologies provided by external libraries in order to protect both the integrity and the confidentiality of the
information stored in memory.

- argon2: used to provide confidentiality for sensitive user data.
- AES: used to provide confidentiality for sensitive contact data.
- scrypt: used to generate the symmetric key for AES encryption from the user's password.
- md5 checksums: used to provide integrity validation both for user data and contact data.
- PGP: using AES and RSA encryption to send encrypted files.

    So far, we are making two assumptions. The first is that the attacker cannot view the SecureDrop.py file itself. The second is that the securitycert*.dat files that
are created during creation and/or modification of *.json files are stored on and delivered from a secure, external certificate authority that the attacker is not able
to modify or view.

This is also just a proof of concept and does not communicate over the network (though, if it could, it would have no secure vulnerabilities).