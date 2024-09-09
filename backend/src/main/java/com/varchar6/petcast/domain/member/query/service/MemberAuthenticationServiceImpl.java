package com.varchar6.petcast.domain.member.query.service;

import com.varchar6.petcast.security.CustomUser;
import com.varchar6.petcast.domain.member.query.vo.RoleVO;
import com.varchar6.petcast.domain.member.query.mapper.MemberMapper;
import com.varchar6.petcast.domain.member.query.vo.MemberVO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service(value="queryMemberAuthenticationService")
public class MemberAuthenticationServiceImpl implements MemberAuthenticationService {
    private final MemberMapper memberMapper;

    @Autowired
    public MemberAuthenticationServiceImpl(MemberMapper memberMapper) {
        this.memberMapper = memberMapper;
    }

    @Override
    public UserDetails loadUserByUsername(String loginId) throws UsernameNotFoundException {
        log.debug("loadUserByUsername called");

        MemberVO loginMember = memberMapper.selectMemberByMemberIdWithAuthority(loginId);

        if (loginMember == null) {
            throw new UsernameNotFoundException(loginId + " not found");
        }

        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (RoleVO roleVO : loginMember.getRoleVOList()) {
            if (roleVO.isActive()) {
                grantedAuthorities.add(new SimpleGrantedAuthority(roleVO.getName()));
            }
        }

        return new CustomUser(
                loginMember.getId(),
                loginMember.getLoginId(),
                loginMember.getPassword(),
                loginMember.getName(),
                loginMember.getPhone(),
                loginMember.getNickname(),
                loginMember.getImage(),
                loginMember.getCreatedAt(),
                loginMember.getUpdatedAt(),
                loginMember.isActive(),
                loginMember.getIntroduction(),
                grantedAuthorities
                );
    }
}
