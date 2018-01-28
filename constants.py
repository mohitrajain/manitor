
# STATES shows different states that client will traverse in order to send data
STATES = { 0 : "Unassociated/Unauthenticated/Unaware_of_ESSID",
           1 : "Unassociated/Unauthenticated/Probe_Req_Res_Done",
           2 : "Unassociated/Authenticated/Probe_Req_Res_Done",
           3 : "Associated/Authenticated/Probe_Req_Res_Done",
           4 : "Action_STA/Pre_Data_Tx_STA",
           5 : "Block_Ack_Ini_STA/Pre_Data_Tx_STA",
           6 : "Data_Tx_STA",
           7 : "Action_AP/Pre_Data_Tx_AP",
           8 : "Block_Ack_Ini_AP/Pre_Data_Tx_AP",
           9 : "Data_Tx_AP"}

# STEPS shows step a ( STATE -1 ) has been completed  
STEPS = { 0 : { 0 : "PROBE_Request",1 : "PROBE_Response" },
          1 : { -1: "LastStepofPrevious",0 : "Authentication_Request", 1 : "Acknowledgment_AP" , 2 : "Authentication_Response" },
          2 : { -1: "LastStepofPrevious",0 : "Association_Request", 1 : "Acknowledgment_AP" , 2 : "Association_Response" },
          3 : { -1: "LastStepofPrevious",0 : "Action_Sent_STA2AP", 1 : "Acknowledgment_AP" , 2 : "Action_Recv_AP2STA" },
          4 : { -1: "LastStepofPrevious",0 : "Block_Ack_Req_STA2AP", 1 : "Block_Ack_Rep_AP2STA" },
          5 : { -1: "LastStepofPrevious",0 : "RTS_STA2AP" , 1 : "CTS_AP2STA" , 2 : "DATA_Tx_STA" , 3 : "Block_Ack_Bitmap_AP2STA" },
          6 : { -1: "LastStepofPrevious",0 : "Action_Recv_AP2STA", 1 : "Action_Sent_STA2AP" , 2 : "Acknowledgment_AP"},
          7 : { -1: "LastStepofPrevious",0 : "Block_Ack_Req_AP2STA", 1 : "Block_Ack_Rep_STA2AP" },
          8 : { -1: "LastStepofPrevious",0 : "RTS_AP2STA" , 1 : "CTS_STA2AP" , 2 : "DATA_Tx_AP" ,  3 : "Block_Ack_Bitmap_STA2AP"  }
          }

DOT11_TYPE_MANAGEMENT = 0
DOT11_TYPE_CONTROL = 1
DOT11_TYPE_DATA = 2

DOT11_SUBTYPE_PROBE_REQ = 0x04
DOT11_SUBTYPE_PROBE_RESP = 0x05

DOT11_SUBTYPE_AUTH = 0x0B

DOT11_SUBTYPE_ASSOC_REQ = 0x00
DOT11_SUBTYPE_ASSOC_RESP = 0x01

DOT11_SUTYPE_ACK = 0x1D
DOT11_SUTYPE_ACTION = 0x0D

DOT11_SUTYPE_BLK_ACK_REQ = 0x18
DOT11_SUTYPE_BLK_ACK_RESP = 0x19

DOT11_SUTYPE_RTS = 0x1B
DOT11_SUTYPE_CTS = 0x1C

DOT11_SUBTYPE_QOS_DATA = 0x28
DOT11_SUBTYPE_DATA = 0x00

Broadcast = 'ff:ff:ff:ff:ff:ff'