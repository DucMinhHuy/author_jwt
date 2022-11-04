package huy.thuchanh2.service;

import huy.thuchanh2.entities.User;
import org.springframework.stereotype.Service;
import org.thymeleaf.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserService {
    public static List<User> listUser=new ArrayList<User>();
    static{
        User userKai=new User(1,"kai","123");
        userKai.setRoles(new String[]{"ROLE_USER"});
        User userHuy=new User(2,"huy","123");
        userHuy.setRoles(new String[] {"ROLE_ADMIN"});
        listUser.add(userHuy);
        listUser.add(userKai);
    }
    public List<User> findAll(){
        return listUser;
    }
    public User findAll(int id){
        for(User user:listUser){
            if(user.getId()==id){
                return user;
            }
        }
        return null;
    }
    public boolean add(User user){
        for(User userExist : listUser){
            if(user.getId()==userExist.getId()|| StringUtils.equals(user.getusername(),userExist.getusername())){
                return false;
            }
        }
        listUser.add(user);
        return true;
    }
    public void delete(int id){
        listUser.removeIf(user -> user.getId()==id);
    }
    public User loadUserByusername(String username){
        for(User user:listUser){
            if(user.getusername().equals(username)) {
                return user;
            }
        }
        return null;
    }
    public boolean checkLogin( User user){
        for(User userExist: listUser){
            if(StringUtils.equals(user.getusername(),userExist.getusername()) &&
            StringUtils.equals(user.getPassword(),userExist.getPassword())){
                return true;
            }
        }
        return false;
    }
}
