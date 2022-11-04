package huy.thuchanh2.controller;

import huy.thuchanh2.entities.User;
import huy.thuchanh2.service.JwtService;
import huy.thuchanh2.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/rest")
public class UserRestController {
    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserService userService;
    // get
    @RequestMapping(value = "/users",method = RequestMethod.GET)
    public ResponseEntity<List<User>> getAllUser(){
        return new ResponseEntity<List<User>>(userService.findAll(), HttpStatus.OK);
    }
    @RequestMapping(value = "/users/{id}",method = RequestMethod.GET)
    public ResponseEntity<Object> getUserbyId(@PathVariable int id){
        User user=userService.findAll(id);
        if(user!=null){
            return new ResponseEntity<Object>(user,HttpStatus.OK);
        }
        return new ResponseEntity<Object>("not found user",HttpStatus.NO_CONTENT);
    }
    @RequestMapping(value = "/users",method = RequestMethod.POST)
    public ResponseEntity<String> createUser(@RequestBody User user){
        if(userService.add(user)){
            return new ResponseEntity<String>("created", HttpStatus.CREATED);
        }else {
            return new ResponseEntity<String>("user existed",HttpStatus.BAD_REQUEST);
        }
    }
    @RequestMapping(value = "/users/{id}",method = RequestMethod.DELETE)
    public ResponseEntity<String> deleteUserById(@PathVariable int id){
        userService.delete(id);
        return new ResponseEntity<String>("delete!",HttpStatus.OK);
    }
    @RequestMapping(value = "/login",method = RequestMethod.POST)
    public ResponseEntity<String> login(HttpServletRequest request,@RequestBody User user) {
        String result = "";
        HttpStatus httpStatus = null;
        try {
            if(userService.checkLogin(user)){
                result = jwtService.generateTokenLogin(user.getusername());
                httpStatus=HttpStatus.OK;
            }else {
                result="Wrong userId and password";
                httpStatus=HttpStatus.BAD_REQUEST;
            }
        }catch (Exception e){
            result="server error";
            httpStatus=HttpStatus.INTERNAL_SERVER_ERROR;
        }
        return new ResponseEntity<String>(result,httpStatus);
    }
}
