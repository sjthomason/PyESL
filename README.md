# PyESL
Pure Python FreeSWITCH Event Socket Client Library

This goals of this implementation are:
- Python 2.7 and 3.4 support
- API compatibility with FreeSWITCH C Python ESL module
- A single file module that is easy to drop into an existing project

## Usage
```python
>>> import ESL
>>> con = ESL.ESLconnection("127.0.0.1", "8021", "ClueCon")
>>> con.api('status').getBody()
>>> con.api('show', 'calls as json').getBody()
```

