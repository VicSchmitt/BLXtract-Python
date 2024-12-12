# BLXtract - Python Adaptation
A python adaptation of Robert Graham's BLXtract tool (originally written in C).
Full credit goes to Robert Graham (repository link: https://github.com/robertdavidgraham/blxtract).

Most code comments are from Robert Graham's C code.
## Summary:
This code extracts data from Dennis Montgomery's BLX file format, released by Mike Lindell's Cyber Symposium.

## Usage:
Process one or more files -
```
Python3 blxtract.py <filename> [<filename> ...]
```

Flags -
+ ``--ordered`` checks each delimiter separately
+ ``--progress`` adds a progress bar


