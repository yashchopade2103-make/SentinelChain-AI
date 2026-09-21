### *SentinelChain Architecture*

\------------------------------------------------------------------------------------------------------------------------------------------------------------



###### 1 High-Level Architecture

###### 

###### At the highest level, SentinelChain consists of four major layers:



┌─────────────────────────────────────────────────────────┐

│                    ATTACK / ACTIVITY                                       │

│              Attacker VM / User Activity                                   │

└──────────────────────────┬──────────────────────────────┘

&#x20;                          ↓

┌─────────────────────────────────────────────────────────┐

│                    DETECTION LAYER                                         │

│                    Wazuh SIEM                                              │

│                                                                            │

│  Wazuh Agent → Wazuh Manager → Detection Rules                             │

│                         ↓                                                  │

│                     Alert Data                                             │

└──────────────────────────┬──────────────────────────────┘

&#x20;                          ↓

┌─────────────────────────────────────────────────────────┐

│                  INVESTIGATION LAYER                                       │

│                  SentinelChain                                             │

│                                                                            │

│  Parser → Investigation Case → 7-Agent Pipeline                            │

└──────────────────────────┬──────────────────────────────┘

&#x20;                          ↓

┌─────────────────────────────────────────────────────────┐

│                    ANALYSIS / AI                                           │

│                                                                            │

│  CrewAI → Ollama → Qwen3                                                   │

│                                                                            │

│  Triage → Evidence → TI → Correlation → Investigation                      │

│           → Counter-Analysis → Final Verdict                               │

└─────────────────────────────────────────────────────────┘



\------------------------------------------------------------------------------------------------------------------------------------------------------------



###### 2 The Lab Environment



###### &#x20;> Attacker VM

###### 

###### The attacker machine generates controlled security activity.

###### 

###### For our main validation scenario, we used:

###### 

###### *Hydra → SSH brute-force simulation*

###### 

###### The important thing is that this was performed against our own lab environment.



\------------------------------------------------------------------------------------------------------------------------------------------------------------



###### > Linux Endpoint

###### 

###### This machine represents a monitored endpoint inside an organization.

###### 

###### It runs:

###### 

###### *Ubuntu*

###### *+*

###### *Wazuh Agent*

###### *+*

###### *SSH*

###### 

###### The Wazuh Agent monitors relevant logs and sends security events to the Wazuh server.

###### 

###### For the SSH test:

###### 

###### *Hydra*

###### &#x20;  *↓*

###### *SSH*

###### &#x20;  *↓*

###### */var/log/auth.log*

###### &#x20;  *↓*

###### *Wazuh Agent*

###### 

###### The endpoint is therefore where the original security activity becomes observable.

###### \----------------------------------------------------------------------------------------------------------------------------



###### > Wazuh SIEM Server

###### 

###### This is the central security monitoring system.

###### 

###### The Wazuh environment contains the components responsible for:

###### 

###### Receiving agent data

###### Processing events

###### Applying detection rules

###### Generating alerts

###### Storing alert data

###### 

###### For our project, Wazuh is essentially the detection engine.

###### 

###### The important architectural distinction is:

###### 

###### *Wazuh = Detection*

###### *SentinelChain = Investigation*



\------------------------------------------------------------------------------------------------------------------------------------------------------------



###### &#x20;> Windows Development Host

###### 

###### During development, SentinelChain itself runs on the Windows host.

###### 

###### This machine runs:

###### 

###### *Python*

###### *CrewAI*

###### *Ollama*

###### *Qwen3*

###### *SentinelChain*

###### 

###### It communicates with the Wazuh server over the network.

###### 

###### So our development architecture looked roughly like:



&#x20;       ┌───────────────────┐

&#x20;       │   Attacker VM           │

&#x20;       │      Hydra              │

&#x20;       └─────────┬─────────┘

&#x20;                 ↓

&#x20;       ┌───────────────────┐

&#x20;       │  Ubuntu Endpoint        │

&#x20;       │    Wazuh Agent          │

&#x20;       └─────────┬─────────┘

&#x20;                 ↓

&#x20;       ┌───────────────────┐

&#x20;       │   Wazuh Server          │

&#x20;       │ Manager + Indexer       │

&#x20;       └─────────┬─────────┘

&#x20;                 │

&#x20;                 │ API / Indexer

&#x20;                 ↓

&#x20;       ┌───────────────────┐

&#x20;       │ Windows Host            │

&#x20;       │ SentinelChain           │

&#x20;       │ CrewAI + Ollama         │

&#x20;       │ + Qwen3                 │

&#x20;       └───────────────────┘

\------------------------------------------------------------------------------------------------------------------------------------------------------------



###### > The Wazuh → SentinelChain Boundary

###### 

###### This boundary is very important.

###### 

###### Wazuh produces a relatively complex alert document.

###### 

###### SentinelChain doesn't want every agent trying to understand that raw structure independently.

###### 

###### Instead:

###### 

###### Raw Wazuh JSON

###### &#x20;      ↓

###### &#x20;  Python Parser

###### &#x20;      ↓

###### Structured Alert

###### &#x20;      ↓

###### Investigation Case

###### &#x20;      ↓

###### AI Agents

###### 

###### This is deliberate.

###### 

###### We don't want:

###### 

###### *Agent 1 → figure out Wazuh JSON*

###### *Agent 2 → figure out Wazuh JSON*

###### *Agent 3 → figure out Wazuh JSON*

###### *Agent 4 → figure out Wazuh JSON*

###### 

###### That would make the system inconsistent.

###### 

###### Instead:

###### 

###### &#x20;             *RAW DATA*

###### &#x20;                *↓*

###### &#x20;             *PARSER*

###### &#x20;                *↓*

###### &#x20;       *STANDARDIZED DATA*

###### &#x20;                *↓*

###### &#x20;         *SHARED CASE*

###### &#x20;          *↙    ↓    ↘*

###### &#x20;       *Agent Agent Agent*

###### 

###### The agents receive a structured investigation case.



\------------------------------------------------------------------------------------------------------------------------------------------------------------



###### &#x20;> The Deterministic Layer

###### 

###### One of the most important design principles in SentinelChain is:

###### 

###### Don't use AI for tasks that can be performed reliably with normal code.

###### 

###### For example:



*Python handles*

*HTTP requests*

*Wazuh communication*

*JSON parsing*

*IOC extraction*

*API authentication*

*Threat-intelligence API calls*

*Validation*

*Data formatting*

*AI handles*

*Interpretation*

*Reasoning*

*Investigative analysis*

*Alternative explanations*

*Evidence assessment*

*Final assessment*



###### So:



&#x20;                   *SentinelChain*

&#x20;                        │

&#x20;            ┌────────┴────────┐

&#x20;            ↓                       ↓

&#x20;      *Deterministic             AI Layer*

&#x20;         *Python                    LLM*

&#x20;            │                       │

&#x20;     *Exact operations            Reasoning*





###### This separation makes the project much more reliable.



\------------------------------------------------------------------------------------------------------------------------------------------------------------



###### > Investigation Case

###### 

###### Once the raw Wazuh alert has been parsed, SentinelChain creates an Investigation Case.

###### 

###### Think of this as the case file that follows the alert through the entire investigation.

###### 

###### Conceptually:

###### 

###### Investigation Case

│

├─*─ Case ID*

├─*─ Alert*

├── *Endpoint*

├── *Network*

├── *User*

├── *Process*

├── *Authentication*

├── *MITRE information*

├── *Evidence*

├── *Timeline*

├── *Triage*

├── *Threat Intelligence*

├── *Findings*

├*── Counter Analysis*

└── *Verdict*

###### 

###### Instead of every agent creating a completely separate data structure, the case progressively gains information.



\------------------------------------------------------------------------------------------------------------------------------------------------------------

###### 

###### > The Seven-Agent Architecture

###### 

###### This is the heart of SentinelChain.



&#x20;                        Investigation Case

&#x20;                               │

&#x20;                               ↓

&#x20;                   ┌──────────────────────┐

&#x20;                   │ Agent 1              │

&#x20;                   │ Alert Triage         │

&#x20;                   └──────────┬───────────┘

&#x20;                              ↓

&#x20;                   ┌──────────────────────┐

&#x20;                   │ Agent 2                     │

&#x20;                   │ Evidence Analysis           │

&#x20;                   └──────────┬───────────┘

&#x20;                                  ↓

&#x20;                   ┌──────────────────────┐

&#x20;                   │ Agent 3                     │

&#x20;                   │ Threat Intelligence         │

&#x20;                   └──────────┬───────────┘

&#x20;                                  ↓

&#x20;                   ┌──────────────────────┐

&#x20;                   │ Agent 4                     │

&#x20;                   │ Correlation                 │

&#x20;                   └──────────┬───────────┘

&#x20;                                  ↓

&#x20;                   ┌──────────────────────┐

&#x20;                   │ Agent 5                     │

&#x20;                   │ Investigation               │

&#x20;                   └──────────┬───────────┘

&#x20;                                  ↓

&#x20;                   ┌──────────────────────┐

&#x20;                   │ Agent 6                     │

&#x20;                   │ Counter-Analysis            │

&#x20;                   └──────────┬───────────┘

&#x20;                                  ↓

&#x20;                   ┌──────────────────────┐

&#x20;                   │ Agent 7                     │

&#x20;                   │ Final Verdict               │

&#x20;                   └──────────┬───────────┘

&#x20;                                  ↓

&#x20;                        Final Assessment



###### Each agent has a specific responsibility.

###### 

###### That separation is intentional.



\------------------------------------------------------------------------------------------------------------------------------------------------------------



###### > CrewAI's Role

###### 

###### We used CrewAI to create and manage the AI agents.

###### 

###### CrewAI provides the framework that lets us define things like:

###### 

###### *Agent*

###### *Role*

###### *Goal*

###### *Backstory*

###### *LLM*

###### *Task*

###### 

###### But CrewAI isn't the intelligence itself.

###### 

###### Think of it like this:

###### 

###### *CrewAI*

###### &#x20;  ↓

###### Agent orchestration framework

###### &#x20;  ↓

###### *Ollama*

###### &#x20;  ↓

###### Qwen3

###### &#x20;  ↓

###### Actual language-model reasoning

###### 

###### So when someone asks:

###### 

###### "What AI model did you use?"

###### 

###### The answer is:

###### 

###### *Qwen3:8B*

###### 

###### When they ask:

###### 

###### "What did you use to orchestrate the agents?"

###### 

###### The answer is:

###### 

###### *CrewAI*

###### 

###### When they ask:

###### 

###### "How did you run the model locally?"

###### 

###### The answer is:

###### 

###### *Ollama*

###### 

###### These are three different components.



\------------------------------------------------------------------------------------------------------------------------------------------------------------

###### 

###### &#x20;> Validation Layer

###### 

###### Another important component is the validation layer.

###### 

###### AI-generated output is not automatically trusted.

###### 

###### For example:



Agent

&#x20;↓

Generated JSON

&#x20;↓

Validator

&#x20;↓

Valid?

&#x20;├── *YES → Continue*

&#x20;└── *NO  → Stop / Handle error*



###### We built validators for multiple stages, including:

###### 

###### Investigation

###### Counter-analysis

###### Final verdict

###### 

###### This protects the pipeline from malformed output.

###### 

###### For example, if the final agent returns:

###### 

{

&#x20; "verdict": "very\_malicious"

}



###### our schema doesn't accept that because the allowed values are:



*benign*

*suspicious*

*malicious*

*inconclusive*



*------------------------------------------------------------------------------------------------------------------------------------------------------------*



###### &#x20;> Complete Data Flow

###### 

###### Now we can combine everything.



┌──────────────────┐

│   Attacker VM    │

│      Hydra       │

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│ Ubuntu Endpoint  │

│   Wazuh Agent    │

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│   Wazuh SIEM     │

│ Detection Rules  │

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│ Wazuh Alert      │

│ Rule 5763        │

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│ Wazuh Indexer    │

│   OpenSearch     │

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│ SentinelChain    │

│ Wazuh Retrieval  │

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│ Python Parser    │

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│ Investigation    │

│ Case             │

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│ Agent 1          │

│ Triage           │

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│ Agent 2          │

│ Evidence         │

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│ Agent 3          │

│ Threat Intel     │◄──── AbuseIPDB

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│ Agent 4          │

│ Correlation      │

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│ Agent 5          │

│ Investigation    │

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│ Agent 6          │

│ Counter-Analysis │

└────────┬─────────┘

&#x20;        ↓

┌──────────────────┐

│ Agent 7          │

│ Final Verdict    │

└────────┬─────────┘

&#x20;        ↓

┌─────────────────────────┐

│ Final SOC Assessment    │

│ Verdict + Confidence    │

│ Evidence + Uncertainty  │

│ Escalation              │

└─────────────────────────┘



\------------------------------------------------------------------------------------------------------------------------------------------------------------







