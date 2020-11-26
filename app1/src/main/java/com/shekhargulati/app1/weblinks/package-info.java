/**
 * https://stackoverflow.com/questions/16510259/using-intercept-url-in-spring-security
 * https://docs.spring.io/spring-security/site/docs/3.0.x/reference/el-access.html
 *
 *
@Controller
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class App1Controller {

    //这种是java configuration(也可以放在security.xml里面用xml configuration)
    @PreAuthorize("hasRole('APPLE')")
    @GetMapping("/apple/hello")
    public String greeting(@RequestParam(name="name", required=false, defaultValue="World") String name, Model model) {
        model.addAttribute("name", name);
        return "hello";
    }
}


 */


/**
 *
 *https://dzone.com/articles/spring-boot-how-to-solve-oauth2-redirect-uri-misma
 * oauth2 client如果使用https或非 /login作为默认redirect_uri的话，则必须要配置下面两个参数(因为如果是https不配置的话，会默认跳转到http://xxx:port/login)
security.oauth2.client.preEstablishedRedirectUri=http://localhost:9090/callback
security.oauth2.client.useCurrentUri=false
 *
 */

/**
 * @author ak
 *
 */
package com.shekhargulati.app1.weblinks;


