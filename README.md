# security-analysis

This repository contains three guided fuzzers to detect heap corruption, stack overflow and injection vulnerabilities. They are all based on the idea of presenting a general vulnerability specification method to separate the vulnerability detection algorithm and the characteristics of the intended vulnerability. 

We model a vulnerabilty as one or more pair of (containers, rule), in which the containers define the place of important data for a vulnerability and the rule defines the condition under which a vulnerabilty is exploited. Using this general model, We define the vulnerability detection problem as a contraint satisfaction problem and detect various vulnerability classes using a guided fuzzer. 

More information is available in the article Towards designing an extendable vulnerability detection method for executable codes at https://www.sciencedirect.com/science/article/abs/pii/S095058491630146X. 