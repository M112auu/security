package com.ma.security.mapper;

import com.ma.security.entity.SysUser;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

@Repository
public interface UserMapper {
    @Select("select * from SysUser where userName = username")
    SysUser findUserByName(@Param("username") String username);
}
