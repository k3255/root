package com.example.tas.demo.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class LogingController {
    private final Logger log = LoggerFactory.getLogger(getClass());

    @RequestMapping(value = "/loging")
    public void home() {
        System.out.println("LogingController loging");

        log.trace("TRACE 로그!!");
        log.debug("DEBUG 로그!!");
        log.info("INFO 로그!!");
        log.warn("WARN 로그!!");
        log.error("ERROR 로그!!");

    }
}