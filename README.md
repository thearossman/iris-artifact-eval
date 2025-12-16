# Iris: Expressive Traffic Analysis for the Modern Internet

Iris is an open-source framework for executing traffic analysis research.

Iris provides high-level abstractions, like [Zeek](https://zeek.org), alongside low-level, performant access to connection data. Iris absorbs the common, tedious tasks associated with traffic analysis, leaving researchers to focus on what is relevant to their use-cases. In experiments on the Stanford University network, we find that Iris can execute hundreds of concurrent, complex analsysis tasks at 100Gbps+ on a single commodity server.

## Iris Programming Framework

An Iris application consists of *one or more* traffic *subscriptions*, each of which consists of filters, data types, and callbacks over tracked connections.

* **Subscription Programming Model.** Iris supports analyzing packets, reassembled streams, and parsed application sessions within a bidirectional, "five-tuple"-defined connection. Each subscription includes a filter (what data is of interest?), a set of data types (what format should the data be delivered in?), and callback (what to do with the data?).

* **User-Defined Filters, Data Types, and Callbacks.** Iris provides complete programmable control over filter predicates, data transformation and construction, and callback (analysis) code.

* **Connection Scope.** Iris scopes subscriptions to inferred connections, i.e., bidirectional packet streams associated with the same five-tuple until a FIN/ACK sequence, RST, or user-configurable inactivity timeout. Connections may not fully establish (i.e., an unanswered SYN is treated as a ``connection'' by \system).
Applications that analyze data across connections can be built on top of \system, much like Iris is built on top of DPDK.

* **State Machines.** To expose both common abstractions and low-level access to connection data, Iris presents connections to user code as a set of protocol-specific state machines that user-defined functions can hook into.
Iris currently supports the states and state transitions described in [DataLevel](core/src/conntrack/conn/conn_state.rs#L29).
Iris processes packets in a connection as they arrive, advancing the connection through its state machines. Note that some events carry data (e.g., observed packet, parsed application headers).

