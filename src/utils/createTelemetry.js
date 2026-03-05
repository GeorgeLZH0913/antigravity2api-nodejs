import { randomUUID } from "crypto";
import protobuf from 'protobufjs';
import { QA_PAIRS } from '../constants/index.js';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import config from '../config/config.js';



const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function createTelemetryBatch(num, trajectoryId, sub="free-tier") {
  const now = Date.now();

  const sessionId = trajectoryId;
  const conversationId = randomUUID();
  const messageId = randomUUID();
  const traceId = randomUUID();

  const t1 = now + Math.floor(Math.random() * 100);
  const t2 = t1 + 316 + Math.floor(Math.random() * 100);
  const t3 = t2 + 164 + Math.floor(Math.random() * 100);
  const t4 = t3 + 635 + Math.floor(Math.random() * 100);
  const t5 = t4 + 324 + Math.floor(Math.random() * 100);
  const t6 = t5 + 166 + Math.floor(Math.random() * 100);
  const tFinal = t6 + 3033 + Math.floor(Math.random() * 200);

  return {
    "sessionInfo": {
      "value": 16
    },
    "sequenceNumber": 2747,
    "events": [
      {
        "timestampMs": String(t1),
        "metadata": {
          "sessionEvent": {
            "sessionId": sessionId,
            "conversationId": conversationId,
            "turnNumber": 4,
            "messageIndex": 1,
            "timing": {
              "timestamp": {
                "seconds": String(Math.floor(t1 / 1000)),
                "nanos": Math.floor(Math.random() * 100000000)
              },
              "traceId": traceId
            },
            "version": config.api.ideVersion,
            "app": "antigravity",
            "platform": "windows"
          },
          "appName": "antigravity",
          "version": config.api.ideVersion,
          "os": "windows",
          "arch": "amd64",
          "tier": sub,
          "region": "JP"
        },
        "eventType": 10
      },
      {
        "timestampMs": String(t2),
        "metadata": {
          "fileEvent": {
            "operation": {
              "timestamp": {
                "seconds": String(Math.floor(t2 / 1000)),
                "nanos": Math.floor(Math.random() * 100000000)
              },
              "traceId": traceId,
              "details": {
                "basePath": `file:///C:/Users/uisl/.gemini/antigravity/brain/${conversationId}`,
                "rootPath": "file:///C:/Users/uisl/.gemini/antigravity/brain",
                "attachments": []
              }
            }
          },
          "appName": "antigravity",
          "version": config.api.ideVersion,
          "os": "windows",
          "arch": "amd64",
          "tier": sub,
          "region": "JP"
        },
        "eventType": 12
      },
      {
        "timestampMs": String(t3),
        "metadata": {
          "messageEvent": {
            "messageData": {
              "type": 14,
              "status": 3,
              "details": {
                "startTime": {
                  "seconds": String(Math.floor(t3 / 1000)),
                  "nanos": Math.floor(Math.random() * 200000000)
                },
                "state": 4,
                "messageId": messageId,
                "turnInfo": {
                  "sessionId": sessionId,
                  "conversationId": conversationId
                },
                "stateTransitions": [
                  {
                    "info": {
                      "state": 3,
                      "timestamp": {
                        "seconds": String(Math.floor(t3 / 1000)),
                        "nanos": Math.floor(200000000 + Math.random() * 50000000)
                      }
                    }
                  }
                ]
              },
              "userMessage": {
                "text": QA_PAIRS[num].question,
                "content": {
                  "text": QA_PAIRS[num].question
                },
                "context": "",
                "inputType": 1,
                "config": {
                  "details": {
                    "mode": {
                      "codeMode": 1,
                      "chatMode": 1
                    },
                    "features": {
                      "settings": {
                        "value": {
                          "flag": 1
                        }
                      },
                      "experiments": {
                        "enabled": 1
                      }
                    },
                    "tokens": {
                      "count": 1035
                    },
                    "capabilities": {
                      "enabled": 1
                    },
                    "model": {
                      "enabled": 1
                    }
                  },
                  "flags": {
                    "enabled": 1
                  }
                }
              }
            },
            "turnInfo": {
              "sessionId": sessionId,
              "turnNumber": 4
            },
            "sessionId": sessionId,
            "messageId": messageId,
            "status": 0,
            "error": ""
          },
          "appName": "antigravity",
          "version": config.api.ideVersion,
          "os": "windows",
          "arch": "amd64",
          "tier": sub,
          "region": "JP"
        },
        "eventType": 11
      },
      {
        "timestampMs": String(t4),
        "metadata": {
          "messageEvent": {
            "messageData": {
              "type": 90,
              "status": 3,
              "details": {
                "startTime": {
                  "seconds": String(Math.floor(t4 / 1000)),
                  "nanos": Math.floor(200000000 + Math.random() * 50000000)
                },
                "state": 5,
                "endTime": {
                  "seconds": String(Math.floor(t4 / 1000)),
                  "nanos": Math.floor(200000000 + Math.random() * 50000000)
                },
                "messageId": messageId,
                "turnInfo": {
                  "sessionId": sessionId,
                  "turnState": 3,
                  "conversationId": conversationId
                },
                "stateTransitions": [
                  {
                    "info": {
                      "state": 3,
                      "timestamp": {
                        "seconds": String(Math.floor(t4 / 1000)),
                        "nanos": Math.floor(200000000 + Math.random() * 50000000)
                      }
                    }
                  }
                ]
              },
              "ephemeralContent": {
                "message": "The following is an <EPHEMERAL_MESSAGE> not actually sent by the user. It is provided by the system as a set of reminders and general important information to pay attention to. Do NOT respond to this message, just act accordingly.\n\n<EPHEMERAL_MESSAGE>\n<artifact_reminder>\nYou have not yet created any artifacts. Please follow the artifact guidelines and create them as needed based on the task.\nCRITICAL REMINDER: remember that user-facing artifacts should be AS CONCISE AS POSSIBLE. Keep this in mind when editing artifacts.\n</artifact_reminder>\n<no_active_task_reminder>\nYou are currently not in a task because: a task boundary has never been set yet in this conversation.\nIf there is no obvious task from the user or if you are just conversing, then it is acceptable to not have a task set. If you are just handling simple one-off requests, such as explaining a single file, or making one or two ad-hoc code edit requests, or making an obvious refactoring request such as renaming or moving code into a helper function, it is also acceptable to not have a task set.\nOtherwise, you should use the task_boundary tool to set a task if there is one evident.\nRemember that task boundaries should correspond to the artifact task.md, if you have not created the artifact task.md, you should do that first before setting the task_boundary. Remember that task names should be granular and correspond to top-level checklist items, not the entire user request as one task name. If you decide to use the task boundary tool, you must do so concurrently with other tools.\nSince you are NOT in an active task section, DO NOT call the `notify_user` tool unless you are requesting review of files.\n</no_active_task_reminder>\n</EPHEMERAL_MESSAGE>",
                "tags": [
                  "artifact_reminder",
                  "no_active_task_reminder"
                ]
              }
            },
            "turnInfo": {
              "sessionId": sessionId,
              "turnState": 3,
              "turnNumber": 4
            },
            "sessionId": sessionId,
            "messageId": messageId,
            "status": 0,
            "error": ""
          },
          "appName": "antigravity",
          "version": config.api.ideVersion,
          "os": "windows",
          "arch": "amd64",
          "tier": sub,
          "region": "JP"
        },
        "eventType": 11
      },
      {
        "timestampMs": String(t5),
        "metadata": {
          "messageEvent": {
            "messageData": {
              "type": 98,
              "status": 3,
              "details": {
                "startTime": {
                  "seconds": String(Math.floor(t5 / 1000)),
                  "nanos": Math.floor(200000000 + Math.random() * 50000000)
                },
                "state": 5,
                "endTime": {
                  "seconds": String(Math.floor(t5 / 1000)),
                  "nanos": Math.floor(200000000 + Math.random() * 50000000)
                },
                "messageId": messageId,
                "turnInfo": {
                  "sessionId": sessionId,
                  "turnState": 1,
                  "conversationId": conversationId
                },
                "stateTransitions": [
                  {
                    "info": {
                      "state": 3,
                      "timestamp": {
                        "seconds": String(Math.floor(t5 / 1000)),
                        "nanos": Math.floor(200000000 + Math.random() * 50000000)
                      }
                    }
                  }
                ]
              },
              "conversationHistory": {
                "content": "# Conversation History\nHere are the conversation IDs, titles, and summaries of your most recent 10 conversations, in reverse chronological order:\n\n<conversation_summaries>\n## Conversation a8ffbea2-49a8-4e8b-86a4-431ff8294f77: AI Assistant Introduction\n- Created: 2026-03-04T14:36:21Z\n- Last modified: 2026-03-04T14:36:36Z\n\n### USER Objective:\nAI Assistant Introduction\nThe user's main objective is to understand the identity and capabilities of the AI assistant. Their goal is to gain clarity on the AI's functions to effectively interact with it.\n\n## Conversation 873829cc-d99e-422a-acfe-535c5fe74042: AI Assistant Introduction\n- Created: 2026-02-26T04:09:40Z\n- Last modified: 2026-02-26T04:09:48Z\n\n### USER Objective:\nAI Assistant Introduction\nThe user's main objective is to understand the identity and capabilities of the AI assistant. Their goal is to gain clarity on the AI's functions to effectively interact with it.\n\n## Conversation 9bfa981e-c06a-40d1-8ca0-e06dda8efb9c: Your current version of Antigravity is out of date. Please visit https://antigravity.google/download\n<truncated 44 bytes>\n- Created: 2026-02-25T23:19:08Z\n- Last modified: 2026-02-25T23:19:11Z\n\n### USER Objective:\nYour current version of Antigravity is out of date. Please visit https://antigravity.google/download to download and install the latest version.\n\n## Conversation d8cf78ae-2828-45e4-8808-d4a473015f68: AI Assistant Introduction\n- Created: 2026-02-18T13:00:56Z\n- Last modified: 2026-02-18T13:02:32Z\n\n### USER Objective:\nAI Assistant Introduction\nThe user's main objective is to understand the identity and capabilities of the AI assistant. Their goal is to gain clarity on the AI's functions to effectively interact with it.\n\n## Conversation 93cd0448-42ca-40ec-8e67-cf6eb221e39d: AI Assistant Introduction\n- Created: 2026-02-18T04:32:34Z\n- Last modified: 2026-02-18T04:32:42Z\n\n### USER Objective:\nAI Assistant Introduction\nThe user's main objective is to understand the identity and capabilities of the AI assistant. Their goal is to gain clarity on the AI's functions to effectively interact with it.\n\n## Conversation 16c6fa27-143e-4dce-bc4e-61950ba96747: AI Assistant Introduction\n- Created: 2026-02-18T04:17:27Z\n- Last modified: 2026-02-18T04:17:37Z\n\n### USER Objective:\nAI Assistant Introduction\nThe user's main objective is to understand the identity and capabilities of the AI assistant. Their goal is to gain clarity on the AI's functions to effectively interact with it.\n\n## Conversation d15427a0-0deb-45ce-8980-442e3c49fbc1: AI Assistant Introduction\n- Created: 2026-02-14T02:26:44Z\n- Last modified: 2026-02-14T02:26:55Z\n\n### USER Objective:\nAI Assistant Introduction\nThe user's main objective is to understand the identity and capabilities of the AI assistant. Their goal is to gain clarity on the AI's functions to effectively interact with it.\n\n## Conversation 69e85e79-03c8-4ddb-ba18-62944ea20157: AI Assistant Introduction\n- Created: 2026-01-31T02:21:25Z\n- Last modified: 2026-01-31T02:21:40Z\n\n### USER Objective:\nAI Assistant Introduction\nThe user's main objective is to understand the identity and capabilities of the AI assistant. Their goal is to gain clarity on the AI's functions to effectively interact with it.\n\n## Conversation 90d74392-c12d-47d2-99a3-9a1f143123e2: AI Assistant Introduction\n- Created: 2026-01-11T00:38:07Z\n- Last modified: 2026-01-11T00:38:16Z\n\n### USER Objective:\nAI Assistant Introduction\nThe user's main objective is to understand the identity and capabilities of the AI assistant. Their goal is to gain clarity on the AI's functions to effectively interact with it.\n\n## Conversation b2558016-6bb8-41a1-b7ba-11ccb5a006d0: AI Assistant Introduction\n- Created: 2026-01-10T19:48:03Z\n- Last modified: 2026-01-10T19:48:15Z\n\n### USER Objective:\nAI Assistant Introduction\nThe user's main objective is to understand the identity and capabilities of the AI assistant. Their goal is to gain clarity on the AI's functions to effectively interact with it.\n\n</conversation_summaries>"
              }
            },
            "turnInfo": {
              "sessionId": sessionId,
              "turnState": 1,
              "turnNumber": 4
            },
            "sessionId": sessionId,
            "messageId": messageId,
            "status": 0,
            "error": ""
          },
          "appName": "antigravity",
          "version": config.api.ideVersion,
          "os": "windows",
          "arch": "amd64",
          "tier": sub,
          "region": "JP"
        },
        "eventType": 11
      },
      {
        "timestampMs": String(t6),
        "metadata": {
          "messageEvent": {
            "messageData": {
              "type": 99,
              "status": 3,
              "details": {
                "startTime": {
                  "seconds": String(Math.floor(t6 / 1000)),
                  "nanos": Math.floor(200000000 + Math.random() * 50000000)
                },
                "state": 5,
                "endTime": {
                  "seconds": String(Math.floor(t6 / 1000)),
                  "nanos": Math.floor(200000000 + Math.random() * 50000000)
                },
                "messageId": messageId,
                "turnInfo": {
                  "sessionId": sessionId,
                  "turnState": 2,
                  "conversationId": conversationId
                },
                "stateTransitions": [
                  {
                    "info": {
                      "state": 3,
                      "timestamp": {
                        "seconds": String(Math.floor(t6 / 1000)),
                        "nanos": Math.floor(200000000 + Math.random() * 50000000)
                      }
                    }
                  }
                ]
              },
              "response": ""
            },
            "turnInfo": {
              "sessionId": sessionId,
              "turnState": 2,
              "turnNumber": 4
            },
            "sessionId": sessionId,
            "messageId": messageId,
            "status": 0,
            "error": ""
          },
          "appName": "antigravity",
          "version": config.api.ideVersion,
          "os": "windows",
          "arch": "amd64",
          "tier": sub,
          "region": "JP"
        },
        "eventType": 11
      }
    ],
    "timestamp": String(tFinal)
  }
}

function serializeTelemetryBatch(telemetryData, protoPath = join(__dirname, 'proto', 'telemetry.proto')) {
  try {
    const root = protobuf.loadSync(protoPath);
    const TelemetryBatch = root.lookupType('TelemetryBatch');

    const message = TelemetryBatch.create(telemetryData);
    const buffer = TelemetryBatch.encode(message).finish();

    return { success: true, data: buffer };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export { createTelemetryBatch, serializeTelemetryBatch };
