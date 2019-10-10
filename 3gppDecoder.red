Red [
    Title: "3GPP DECODER"
    Author: "KONGLONG"
    Date: 2019-10-01
    Version: 1.0.0
    purpose: "解码wireshark能支持的所有协议"
    Needs:   'View
]

default_config: make map! [
    wireshark-dir: "C:/Program Files/Wireshark"
    notepadpp-dir: "C:/Program Files/Notepad++"
    NAT: [
        #(LTE: [
            "lte-rrc.dl.ccch" "lte-rrc.dl.dcch" "lte-rrc.ul.ccch" "lte-rrc.ul.dcch" "s1ap" "x2ap"
            ])
        #(NR: [
            "nr-rrc.dl.ccch" "nr-rrc.dl.dcch" "nr-rrc.ul.ccch" "nr-rrc.ul.dcch" "xnap"
            ])
        ]
    ]

if error? try [
        config: load-json read %3gppDecoder.cfg
    ][
        config: default_config
    ]
print config
; print ? config/NAT/1/LTE
if error? try [
        ws_path: config/wireshark-dir
        text2pcap: rejoin[config/wireshark-dir "/text2pcap.exe"]
        tshark: rejoin[config/wireshark-dir "/tshark.exe"]
        notepad: rejoin[config/notepadpp-dir "/notepad++.exe"]
    ][
        quit
    ]
; print ws_path
; print text2pcap
; print tshark
; print length? tshark

nats: make block! []
foreach p config/NAT [
    foreach [k v] p [
        append nats to-string k
    ]
]

default_nat: nats/2

if empty? nats [
    quit
]

selected-proto: ""

proc-hex-str: function [
    src-str [string!]
] [
    whitespace: charset reduce [space tab cr lf]
    hex-digits: charset ["0123456789" #"a" - #"f" #"A" - #"F"]

    replace/all src-str "," " "
    replace/all src-str "0x" " "
    replace/all src-str "0X" " "

    dst-str: ""
    hex-ind: 0
    str-len: 0
    clear dst-str

    parse src-str [some[
        some[whitespace] (hex-ind: 0)
        | [pos: hex-digits] (either hex-ind == 0 [
            append dst-str " 0"
            append dst-str pos/1
            str-len: str-len + 3
            hex-ind: 1
            ] [
                dst-str/(:str-len - 1): dst-str/:str-len
                dst-str/:str-len: pos/1
                hex-ind: 0
            ])
    ]]

    trim/head dst-str
    trim/tail dst-str
    dst-str
]

pre-proc-data: function [
    data [string!]
] [
    data: proc-hex-str data
    prep-area/text: data
    rejoin["0000 " data " 0000"]
]

decode-handler: function [
    proto [string!]
    data [string!]
] [
    data-temp: copy data
    data-temp: pre-proc-data data-temp
    write %textdata.txt data-temp
    text2pcap_cmd: rejoin[text2pcap " -l 147 textdata.txt decode_temp.pcap"]
    ; print text2pcap_cmd
    call/wait text2pcap_cmd

    ;^(22)是"的转义，^(5c)是\的转义
    tshark_cmd: rejoin[tshark " -V -o ^(22)uat:user_dlts:^(5c)^(22)User 0 (DLT=147)^(5c)^(22),^(5c)^(22)"
    proto
    "^(5c)^(22),^(5c)^(22)0^(5c)^(22),^(5c)^(22)^(5c)^(22),^(5c)^(22)0^(5c)^(22),^(5c)^(22)^(5c)^(22)^(22) -r decode_temp.pcap"]
    ; print tshark_cmd
    write %decode_result.txt "" 
    call/wait/output tshark_cmd %decode_result.txt

    call/wait "del textdata.txt"
    call/wait "del decode_temp.pcap"

    output-area/text: read %decode_result.txt
]

update-nat-proto: function [
    nat-str [string!]
] [
    foreach p config/NAT [
        foreach [k v] p [
            if nat-str = to-string k [
                proto-drop-down/text: v/1
                proto-drop-down/data: v
            ]
        ]
    ]
]

about-txt: {
版本: v1.0.0
通过修改配置文件，理论上可以解码wireshark支持的所有协议。
                  By: KONGLONG
}

main-window: layout [
    title "3GPP解码器"
    text "网络：" 40x25
    nat-drop-down: drop-down 100x25 data nats
    on-select [
        update-nat-proto face/text
        selected-proto: proto-drop-down/text
    ]
    text "协议：" 40x25
    proto-drop-down: drop-down 125x25 data []
    on-select [
        selected-proto: face/text
    ]
    button "解码" [
        if selected-proto <> "" [
            decode-handler selected-proto input-area/text
        ]
    ]
    button "用NPP打开" [
        call rejoin[notepad " decode_result.txt"]
    ]
    return
    text "输入码流："
    return
    input-area: area focus "" 800x60
    return
    text "码流预处理："
    return
    prep-area: area "" 800x60
    return
    text "解码结果："
    return
    output-area: area "" 800x400

    do [
        nat-drop-down/text: nats/1
        update-nat-proto nat-drop-down/text
        selected-proto: proto-drop-down/text
    ]
]

main-window/menu: [
    "文件" [ "退出" qt ]
    "帮助" [ "关于" ab ]
    ]
main-window/actors: make object! [
    on-menu: func [face [object!] event [event!]][ 
    switch event/picked [
        qt [quit]
        ab [
            view/flags [
                title "关于"
                text 180x100 about-txt
                return
                OK-btn: button "OK" [unview]
                ] [modal popup]
            ]
            ] ] ]

view main-window

