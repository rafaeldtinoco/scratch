#!/bin/bash

echo """
defaults {
    polling_interval 10
    path_selector \"round-robin 0\"
    path_grouping_policy group_by_prio
    uid_attribute \"ID_SERIAL\"
    # getuid_callout \"/lib/udev/scsi_id --whitelisted --device=/dev/%n\"
    prio \"alua\"
    # prio_args \"timeout=1000 preferredsds=foo\"
    features \"0\"
    #features   \"1 queue_if_no_path\"
    #features   \"1 no_partitions\"
    #features   \"2 queue_if_no_path no_partitions\"
    path_checker directio
    rr_min_io 100
    rr_min_io_rq 1
    flush_on_last_del yes
    max_fds 8192
    rr_weight priorities
    failback immediate
    no_path_retry fail
    queue_without_daemon no
    user_friendly_names yes
    mode 0644
    uid 0
    gid disk
    # default : taken from /sys/block/sd<x>/device/timeout
    # checker_timeout 60
    fast_io_fail_tmo 5
    dev_loss_tmo 120
    bindings_file \"/etc/multipath/bindings\"
    wwids_file \"/etc/multipath/wwids\"
    #reservation_key \"59550000\"
    force_sync yes
    delay_watch_checks 12
}


multipaths {
    multipath {
        wwid 3600140530c6d6a71f354e3a88ddf2153
        alias volume01
    }
    multipath {
        wwid 360014059aff8282fd834bf4a3cd5cfc5
        alias volume02
    }
    multipath {
        wwid 360014055f220cec1a5045b681a24a3ed
        alias volume03
    }
    multipath {
        wwid 36001405a3ead61b0fc24a8890fa0c7ad
        alias volume04
    }
    multipath {
        wwid 360014057a9b2aeda42d4f1daa6d7fe05
        alias volume05
    }
    multipath {
        wwid 36001405de05e2dac8e04f7880402ce67
        alias volume06
    }
    multipath {
        wwid 36001405b18f103e9cfb48008d301ca52
        alias volume07
    }
    multipath {
        wwid 36001405a24ecee663f84180a281c56c0
        alias volume08
    }
    multipath {
        wwid 360014050eab28e0a5aa4984ab133f7d8
        alias volume09
    }
    multipath {
        wwid 3600140564d579cf0bad44f39c283172b
        alias volume10
    }

    multipath {
        wwid 3600140571b311b3764946e39778f7165
        alias volume99
    }
}
""" | sudo tee /etc/multipath.conf

sudo systemctl enable --now multipathd.service
sudo systemctl restart multipathd.service

sudo multipath -rF
sleep 1
sudo multipath -ll

