#!/usr/bin/env python3
"""SS7 MAP message decoder - Research module"""

# MAP Operation Codes
MAP_OPCODES = {
    2:  "updateLocation", 3:  "cancelLocation", 4:  "provideRoamingNumber",
    5:  "noteSubscriberPresent", 6:  "resumeCallHandling", 7:  "insertSubscriberData",
    8:  "deleteSubscriberData", 9:  "sendParameters", 10: "registerSS",
    11: "eraseSS", 12: "activateSS", 13: "deactivateSS", 14: "interrogateSS",
    17: "authenticationFailureReport", 18: "updateGprsLocation",
    22: "sendRoutingInfo", 23: "sendRoutingInfoForGprs",
    26: "noteInternalHandover", 29: "sendAuthenticationInfo",
    35: "processUnstructuredSS-Request", 36: "unstructuredSS-Request",
    38: "sendRoutingInfoForSM", 44: "reportSM-DeliveryStatus",
    45: "noteSubscriberDataModified", 46: "restoreData",
    47: "sendRoutingInfoForLCS", 71: "provideSubscriberInfo",
    72: "anyTimeInterrogation", 73: "ss-InvocationNotification",
}

def decode_opcode(code: int) -> str:
    return MAP_OPCODES.get(code, f"Unknown({code})")

def decode_hex_message(hex_str: str) -> dict:
    try:
        data = bytes.fromhex(hex_str.replace(" ", ""))
        result = {"raw_bytes": len(data), "hex": hex_str[:40] + "..."}
        if len(data) > 2:
            result["first_byte"] = f"0x{data[0]:02X}"
            result["possible_opcode"] = decode_opcode(data[0])
        return result
    except Exception as e:
        return {"error": str(e)}
