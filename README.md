This library for ink! contracts gives the client the functionality to
assign dynamic roles to accounts. The principal use-case for it is
allowing or denying certain accounts calling certain messages.

Functionality is a subset of openzeppelin's ethereum
access-control[1], missing some stuff like admin roles (being
considered) and having a hard-cap of 128 roles (for now) :)

In active development, do not use (・`ω´・)

- [1] https://docs.openzeppelin.com/contracts/2.x/access-control#role-based-access-control
