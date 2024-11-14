package com.example.tas.demo.controller;

import com.example.tas.demo.service.CasService;
import com.example.tas.demo.vo.*;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

@RestController
//@RequestMapping(path = "/opendid/cas/api/v1/common")
public class CasController {
    private final Logger log = LoggerFactory.getLogger(getClass());
    @Autowired
    CasService testService;

    @GetMapping(value = "/")
    public ModelAndView index() {
        ModelAndView mav = new ModelAndView();
        mav.setViewName("index");
        return mav;
    }

    @PostMapping("/")
    public ResponseVo trade2(@RequestBody RequestVo request, HttpServletRequest httpRequest) {
        log.info("path : " + httpRequest.getServletPath());
        log.info(request.toJson());
        return testService.test(request);
    }

    @PostMapping("/opendid/cas/api/v1/common/trade")
    public ResponseVo trade(@RequestBody RequestVo request, HttpServletRequest httpRequest) {
        log.info("path : " + httpRequest.getServletPath());
        log.info(request.toJson());
        return testService.test(request);
    }

    @PutMapping("/opendid/cas/api/v1/common/trade/{txId}")
    public ResponseVo trade(@PathVariable("txId") String txId, @RequestBody RequestVo request) {
        System.out.println("txID : " + txId);
        return testService.test(request);
    }
}
