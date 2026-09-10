# Disclaimer

py-file-server is provided **AS IS**, without warranty of any kind, express or
implied. **Use it entirely at your own risk.**

This tool exposes a folder on your machine over the network. Anyone who can
reach the port can list and download the files in that folder, and an
authenticated admin can upload, rename and delete them. Used carelessly it can
expose private data to your whole network or destroy files you did not intend
to lose.

The author accepts no liability for data loss, data corruption, unauthorised
access or disclosure of files, business interruption, or any other direct or
consequential damages arising from the use of this software.

You are responsible for:

- verifying which folder you are exposing before you start the server;
- setting `ADMIN_PASSWORD` to a strong value rather than leaving the default;
- restricting the server to a network you trust (it binds all interfaces);
- keeping tested backups of anything reachable through the shared folder;
- being authorised to share the files you are sharing.

This software is not certified for regulated, forensic, safety-critical or
high-assurance use.

`LICENSE` is the governing legal text and prevails wherever it and this
plain-language summary differ.
