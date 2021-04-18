Red [
    Title: "3GPP DECODER"
    Author: "KONGLONG"
    Date: 2019-10-01
    Version: 1.1.0
    purpose: "解码wireshark能支持的所有协议"
    Needs:   'View
]

warn-button-popup: function [
    tt msg [string!]
]  [
    view/flags [
        title tt
        on-close [quit] 
        msg-text: text font-color red msg center wrap return
        no-btn: button "退出" [quit]
        do [
            msg-text/size/y: msg-text/size/y * 2
            win-centre: (2 * msg-text/offset/x + msg-text/size/x) / 2
            no-btn/offset/x: to integer! win-centre - to integer! (no-btn/size/x / 2)
        ]
    ] [modal popup]
]

if error? try [
        config-data: read %3gppDecoder.cfg
    ][
        warn-button-popup "错误" "在3gppDecoder安装目录下找不到配置文件（3gppDecoder.cfg）"
    ]

if error? try [
        config: load-json config-data
    ][
        warn-button-popup "错误" "加载配置文件（3gppDecoder.cfg）时发生错误，请检查配置文件JSON格式"
    ]

print config

ws-dir: config/wireshark-dir
if ws-dir = none [
        warn-button-popup "错误" "配置文件中的wireshark路径不对，请检查配置文件（3gppDecoder.cfg）"
    ]
replace/all ws-dir "^(5c)" "/"
replace/all ws-dir "//" "/"

npp-dir: config/notepadpp-dir
if npp-dir = none [
        warn-button-popup "错误" "配置文件中的notepadpp路径不对，请检查配置文件（3gppDecoder.cfg）"
    ]
replace/all npp-dir "^(5c)" "/"
replace/all npp-dir "//" "/"

print ws-dir
print npp-dir

if not equal? last ws-dir #"/" [
    ws-dir: append ws-dir "/"
]
if not equal? last npp-dir #"/" [
    npp-dir: append npp-dir "/"
]
print ws-dir
print npp-dir

wireshark-app: rejoin[ws-dir "Wireshark.exe"]
text2pcap-app: rejoin[ws-dir "text2pcap.exe"]
tshark-app: rejoin[ws-dir "tshark.exe"]
notepad-app: rejoin[npp-dir "notepad++.exe"]

print wireshark-app
print text2pcap-app
print tshark-app
print notepad-app

check-file-exist: func [
    file-dir [string!]
    file-name [string!]
] [
    wireshark-app-exist: false
    if error? try [
        folder: read to-file file-dir
        foreach f folder [
            if find f file-name [
                wireshark-app-exist: true
                break
            ]
        ]
        ][
            wireshark-app-exist: false
        ]
    if not wireshark-app-exist [
            error-msg: rejoin["在目录" file-dir "下找不到" file-name "，请检查配置文件（3gppDecoder.cfg）或者" file-name "安装目录"]
            warn-button-popup "错误" error-msg
        ]
]

check-file-exist ws-dir "Wireshark.exe"
check-file-exist ws-dir "text2pcap.exe"
check-file-exist ws-dir "tshark.exe"
check-file-exist npp-dir "notepad++.exe"

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
    ; prep-area/text: data
    rejoin["0000 " data " 0000"]
]


wireshark-cmd-arg1: {"uat:user_dlts:\"User 0 (DLT=147)\",\"}
wireshark-cmd-arg2: {\",\"0\",\"\",\"0\",\"\""}

decode-handler: function [
    proto [string!]
    data [string!]
] [
    data-temp: copy data
    data-temp: pre-proc-data data-temp
    write %textdata_temp.txt data-temp
    text2pcap_cmd: rejoin[text2pcap-app " -l 147 textdata_temp.txt decode_temp.pcap"]
    ; print text2pcap_cmd
    call/wait text2pcap_cmd

    ;^(22)是"的转义，^(5c)是\的转义
    tshark_cmd: rejoin["^(22)" tshark-app "^(22) -V -o " wireshark-cmd-arg1 proto wireshark-cmd-arg2 " -r decode_temp.pcap"]
    print tshark_cmd
    write %decode_result.txt "" 
    call/wait/output tshark_cmd %decode_result.txt

    call/wait "del textdata_temp.txt"
    ; call/wait "del decode_temp.pcap"

    output-area/text: read %decode_result.txt
]

open-wireshark-handler: function [
    proto [string!]
    data [string!]
] [
    data-temp: copy data
    data-temp: pre-proc-data data-temp
    write %textdata_temp.txt data-temp
    text2pcap_cmd: rejoin[text2pcap-app " -l 147 textdata_temp.txt decode_temp.pcap"]
    ; print text2pcap_cmd
    call/wait text2pcap_cmd

    ;^(22)是"的转义，^(5c)是\的转义
    wireshark_cmd: rejoin["^(22)" wireshark-app "^(22) -o " wireshark-cmd-arg1 proto wireshark-cmd-arg2 " -r decode_temp.pcap"]
    print wireshark_cmd
    call/shell wireshark_cmd

    call/wait "del textdata_temp.txt"
    ; call/wait "del decode_temp.pcap"
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
版本: v1.1.0
源码地址: 
https://gitee.com/konglinglong/3gppDecoder
面向未来的3GPP解码器，通过修改配置文件，理论上可以解码wireshark现在以及以后支持的所有协议。
                                  指导: XuBin
                                  跑腿: KONGLONG
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
    button "用notepad++打开" [
        call rejoin[notepad-app " decode_result.txt"]
    ]
    button "用wireshark打开"[
        open-wireshark-handler selected-proto input-area/text
    ]
    button "清空" [
        input-area/text: ""
        ; prep-area/text: ""
        output-area/text: ""
        clear input-area/text
        ; clear prep-area/text
        clear output-area/text
    ]
    return
    text "输入码流："
    return
    input-area: area focus "" 800x60
    ; return
    ; text "码流预处理："
    ; return
    ;prep-area: area "" 800x60
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
                text 300x160 about-txt
                return
                OK-btn: button "OK" [unview]
                ] [modal popup]
            ]
            ] ] ]

view main-window


