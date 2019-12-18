I included five paths in the API.

'/api/newpass' Accepts an JSON object (in the body request) with 4 properties as such:

{
"publicKey": ...,
"passwordFor": ...,
"usernameOrEmail": ...,
"password": ...
}

If there is a publicKey it will encrypt the password. If the value of publicKey is left as an empty string it will leave password unencrypted. The user will utlimately be returned a confirmation of a successful save in the form of a boolean:

####

'/api/passinfo' Accepts a JSON object (in the body request) with 2 properties as such:

{
"passwordFor": ...,
"privateKey": ...
}

(if no privatKey value is left an empty string encrypted passwords will remain encrypted.
)
and ultimately returns a single password info object as such:

{
passwordFor: ...,
usernameOrEmail: ...,
password: ...,
strength: ...,
pwnedInfo: ...,
encrypted: ...
}

####

'/api/listpass' Accepts a JSON object (in the body request) with 1 properties as such:

{
"privateKey": ...
}

(if no privateKey is provided or the privatKey value is left an empty string encrypted passwords will remain encrypted.
)
and ultimately returns an array of all password info objects as such:
[
{
passwordFor: ...,
usernameOrEmail: ...,
password: ...,
strength: ...,
pwnedInfo: ...,
encrypted: ...
},
{
passwordFor: ...,
usernameOrEmail: ...,
password: ...,
strength: ...,
pwnedInfo: ...,
encrypted: ...
},
{
passwordFor: ...,
usernameOrEmail: ...,
password: ...,
strength: ...,
pwnedInfo: ...,
encrypted: ...
}
]

####

'/api/strength' Accepts a password in a query parameter as such:

/api/strength?password=...

and ultimately returns an object as such:
{
score: ...,
crackTimes: ...
};
as determined by the zxcvbn npm package

####

'/api/checkpwned' Accepts a password in a query parameter as such:

/api/checkpwned?password=...

and ultimately returns an string as such:
either: `Found ${found.count} occurences of password breaches`
or: 'No password breaches found'
as determined by the haveibeenpwned api

####

'/api/genkeys' does not need anything passed to it.
Ultimately the user will recieve an object (with public key and private key) such:

{
public: ...,
private: ...
}

I included pre-made test data (test_data.txt) organized by newpass, listpass, and passinfo paths. Simply copy and paste into body to test respective paths.

I do understand that my implementation of public key encryption is far from acceptable in any production setting, however it does work in this limited capacity.
