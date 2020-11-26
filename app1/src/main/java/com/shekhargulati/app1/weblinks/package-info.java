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
 * @author ak
 *
 */
package com.shekhargulati.app1.weblinks;


