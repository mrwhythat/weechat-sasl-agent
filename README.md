# WeeChat SASL agent

Experimental protocol for WeeChat delegated SASL authentication. Agent is
an external program that implements the following interface:

- when called without arguments, return fixed name of the SASL mechanism,
which will be forwarded by WeeChat to the authenticating server to initiate
the process of identification;

- when called with two arguments, namely `key` and `data`, compute some 
result based on the selected mechanism, assument `data` is a challenge supplied
by server; resulting data will be forwarded by WeeChat to the authenticating 
server in order to complete identification.

For WeeChat-side implementation of the protocol see weechat/weechat#1170.
