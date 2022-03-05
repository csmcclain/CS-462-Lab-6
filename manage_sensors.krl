ruleset manage_sensors {

    meta {
        use module io.picolabs.wrangler alias wrangler
        use module io.picolabs.subscription alias subs
        shares sensors, get_temperatures
    }

    global {

        sensors = function() {
            ent:sensors
        }

        generate_name = function() {
            <<Sensor #{random:uuid}>>
        }

        get_temperatures = function() {
            ent:sensors.values().map(function(data) {

                wrangler:picoQuery(data{"eci"}, "temperature_store", "temperatures")
            })
        }

        defaultThreshold = 75
        defaultSMSReceiver = "8013191995"

        tags = ["sensor"]
        event_policy = {
            "allow": [{"domain": "*", "name": "*"}],
            "deny": []
        }
        query_policy = {
            "allow": [{"rid": "*", "name": "*"}]
        }
    }

    rule init {
        select when wrangler ruleset_installed

        if (ent:sensors) then noop()
        
        notfired {
          ent:sensors := {}
        }
      }

    rule add_sensor {
        select when sensor new_sensor

        pre {
            newSensorName = generate_name()
            exists = ent:sensors{newSensorName} != null
        }

        if (exists) then noop()

        notfired {
            raise wrangler event "new_child_request" attributes {
                "name": newSensorName,
                "backgroundColor": "#ffa500"
            }
        }
    }

    rule new_sensor_created {
        select when wrangler new_child_created

        pre {
            name = event:attrs{"name"}.klog("sensor_created new child name: ")
            childID = event:attrs{"eci"}.klog("new child eci: ")
        }

        if name && childID then noop()

    }

    rule initialize_picolabs_emitter_ruleset {
        select when wrangler new_child_created

        pre {
            eci = event:attrs{"eci"}
        }

        event:send(
            {
                "eci": eci,
                "eid": "install-ruleset",
                "domain": "wrangler", "type": "install_ruleset_request",
                "attrs": {
                    "absoluteURL": meta:rulesetURI,
                    "rid": "io.picolabs.wovyn.emitter",
                    "config": {}
                }
            }
        )
    }

    rule initialize_wovyn_ruleset {
        select when wrangler new_child_created

        pre {
            eci = event:attrs{"eci"}
        }

        event:send(
            {
                "eci": eci,
                "eid": "install-ruleset",
                "domain": "wrangler", "type": "install_ruleset_request",
                "attrs": {
                    "absoluteURL": meta:rulesetURI,
                    "rid": "wovyn_base",
                    "config": {}
                }
            }
        )
    }

    rule initialize_temperature_store_ruleset {
        select when wrangler new_child_created

        pre {
            eci = event:attrs{"eci"}
        }

        event:send(
            {
                "eci": eci,
                "eid": "install-ruleset",
                "domain": "wrangler", "type": "install_ruleset_request",
                "attrs": {
                    "absoluteURL": meta:rulesetURI,
                    "rid": "temperature_store",
                    "config": {}
                }
            }
        )
    }
    
    rule initialize_sensor_profile_ruleset {
        select when wrangler new_child_created

        pre {
            name = event:attrs{"name"}
            eci = event:attrs{"eci"}
        }

        event:send(
            {
                "eci": eci,
                "eid": "install-ruleset",
                "domain": "wrangler", "type": "install_ruleset_request",
                "attrs": {
                    "absoluteURL": meta:rulesetURI,
                    "rid": "sensor_profile",
                    "config": {},
                    "name": name
                }
            }
        )
    }

    rule configure_child_sensor_profile{
        select when wrangler child_initialized

        pre {
            eci = event:attrs{"eci"}
            name = event:attrs{"name"}
        }

        event:send(
            {
                "eci": eci,
                "eid": "configure-ruleset",
                "domain": "sensor", "type": "profile_update",
                "attrs": {
                    "SMS_receiver": defaultSMSReceiver,
                    "threshold": defaultThreshold,
                    "location": "unspecified",
                    "name": name
                }
            }
        )
    }

    rule remove_sensor {
        select when sensor unneeded_sensor

        pre {
            sensorName = event:attrs{"name"}.klog("received sensor name to remove: ")
            eci = ent:sensors{sensorName}{"eci"}
            exists = ent:sensors && eci != null
        }

        if exists then noop()

        fired {
            raise wrangler event "child_deletion_request" attributes {
                "eci": eci
            }
            clear ent:sensors{sensorName}
        }
    }

    rule flush_sensors {
        select when sensor flush_sensors

        always {
            ent:sensors := {}
        }
    }

    // Start for Lab 2

    rule identify_child_wellknown {
        select when sensor identify

        pre {
            name = event:attrs{"name"}
            eci = event:attrs{"eci"}.klog("Now got eci for child: ")
            wellKnown = event:attrs{"wellKnown_eci"}
        }

        always {
            ent:sensors{name} := {
                "eci": eci,
                "wellKnown_eci": wellKnown
            }

            // Raise an event to create a subscription with new child
            raise manage_sensors event "sensor_subscription_request" attributes {
                "sensor_name": name
            }
        }
    }

    rule create_sensor_subscription {
        select when manage_sensors sensor_subscription_request

        pre {
            sensor_name = event:attrs{"sensor_name"}
            sensor_wellKnown_Rx = event:attrs{"wellKnown_Rx"} == null => ent:sensors{sensor_name}{"wellKnown_eci"} | event:attrs{"wellKnown_Rx"}
        }

        event:send({"eci": subs:wellKnown_Rx(){"id"},
            "domain":"wrangler", "name":"subscription",
            "attrs": {
                "wellKnown_Tx":sensor_wellKnown_Rx,
                "Rx_role":"Manager", "Tx_role":"Sensor",
                "name": sensor_name+"-subscription", "channel_type":"subscription"
            }
        })


    }
}