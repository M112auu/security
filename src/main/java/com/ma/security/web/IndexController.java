package com.ma.security.web;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class IndexController {
    /**
     * 跳转首页
     */
    @GetMapping("")
    public void index1(HttpServletResponse response){
        //内部重定向
        try {
            response.sendRedirect("/index");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 首页
     */
    @RequestMapping("/index")
    @ResponseBody
    public String index() {
        return "index";
    }

    @RequestMapping("/loginPage")
    public String login() {
        return "login";
    }

    @RequestMapping("/whoim")
    @ResponseBody
    public Object whoIm()
    {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
