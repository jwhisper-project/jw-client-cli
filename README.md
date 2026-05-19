# JWhisper Client CLI

JWhisper Client CLI is a part of JWhisper platform, providing a CLI client.
It's used for sending messages to other users via relay server.

## Prerequisites

To run the app you need to have `JDK 25+` installed.

To build the app from sources you will also need some modern version of `Maven 3.X` installed.

## Build

To build the app use the next command:
```bash
mvn clean package
```

Output is the `.zip` file in `target` folder.
Unpack the ZIP archive where you want the app to live.

Done!

## Run

### Server run

Before using the client application, you should set up and run relay server.

### Client run

To run the app execute the next command:
```bash
java -jar jw-client-cli-1.0.0.jar
```

#### Initialization

You will be prompted to enter username.
It will be used to register on the server — it's yours unique (per-session) identifier.

Then, depending on existence of your identity key store (i.e. whether it's your first execution or not),
you will be prompted to enter either password to existing key store or password for a new key store.
This process should ensure existence of `identity.p12` key store, where your personal signing and encryption keys
will be stored. **Do not forget the password!**

Then, if it's your first execution, you will be prompted to provide configuration data
like server's `hostname` and `port`. These data will be stored in `config.json` file, 
where you're free to change them in the future.

After that you will be asked if you want to add a new SSL certificate to trust store, i.e. if you want to
add one more certificate to list of trusted ones (by default it's empty).
The certificates are stored in the `truststore.p12` file (automatically created if it doesn't exist),
which makes **the whitelist** of trusted certificates/servers to avoid communication
with unknown/untrusted servers. So, I want to add one more trusted certificate (required for the first time),
you will be prompted to provide the certificate in PEM format in a single line.

Now client should be running.

#### Chat

If you (client) has successfully connected to the server, you can proceed to chatting with other registered users.

To do so, you need first to know username of the user you want to send message to. Also, this user should be online.

To send the message, use the next command:
```jwcommand
/msg user123 Hello, my friend! How are you doing?
```
, where `user123` is the recipient's username and everything after it is the message.

If you sent a message and see **error**, it with high probability means the end user is offline.
Otherwise, you will see "*Message sent to user123*", which means the message was sent successfully.

If somebody writes a message to you, you should see in the console message like
```text
Message received from user456: Hello, my friend! How are you doing?
```
, where `user456` is the username of the user who has sent you the message.
You can use it to send the answer.

#### Finish

When you want to close the session, run the next command:
```jwcommand
/exit
```
You will be unregistered and disconnected from the server.

## Communication

Whole communication with relay and end clients in encrypted.
Moreover, end-to-end communication (messages between individual users) is end-to-end encrypted (E2EE),
which effectively means nobody (even relay server) **can't read the messages**. To read the messages you should
own the private keys of the recipient, otherwise it's impossible to read them. All the messages are also signed
using the sender's private key, which ensures that the message was actually sent by the sender mentioned
in the message.

TL;DR communication between users is secure and no one else can read your messages.

## Developer docs

To build the `javadoc` you can use the next command:
```bash
mvn clean javadoc:aggregate
```
