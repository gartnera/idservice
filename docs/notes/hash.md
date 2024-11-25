# Hash

We hash service user IDs to preserve privacy. The main thing we want to prevent is associating one user with another user. We need to specifically guard against scenarios where someone has a list of all user ids on a service.

Example:

Twitter username: `sha256(hazroot) = ee2ac2676e6d94029cd660f3a1e3885a209d778c367ecb0770c15750f8170d2b`

We store your userid and the username hash in the database. You could link to your profile via hash:

http://url.example/profile?service=twitter&hash=ee2ac2676e6d94029cd660f3a1e3885a209d778c367ecb0770c15750f8170d2b.

Or via name:

http://url.example/profile?service=twitter&name=hazroot.

We then pull all other records for matching your userid. We return information about the user but never expose the hash of the service ID. If someone had a list of all usernames for that service, the could easily deanonomize a user.