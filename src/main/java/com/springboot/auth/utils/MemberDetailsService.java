package com.springboot.auth.utils;

import com.springboot.exception.BusinessLogicException;
import com.springboot.exception.ExceptionCode;
import com.springboot.member.entity.Member;
import com.springboot.member.repository.MemberRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Optional;

//DB에서 사용자의 크리덴셜 조회 -> AuthenticationManager 에게 전달
//Custom UserDetailsService
@Component
public class MemberDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;
    private final AuthorityUtils authorityUtils;

    public MemberDetailsService(MemberRepository memberRepository, AuthorityUtils authorityUtils) {
        this.memberRepository = memberRepository;
        this.authorityUtils = authorityUtils;
    }

    //UserDetailsService의 추상메서드를 구현해야한다.
    //인증하려는 사용자의 이메일(username)을 찾고 UserDetails 타입으로 반환한다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //데이터베이스에 해당 이메일(username)이 저장되어있는지 찾는다.
        Optional<Member> optionalMember = memberRepository.findByEmail(username);
        Member findMember = optionalMember.orElseThrow(()
                -> new BusinessLogicException(ExceptionCode.MEMBER_NOT_FOUND));

        //찾은 멤버를 MemberDetails클래스를 이용하여 UserdDetails타입으로 변환시킨 후 반환
        return new MemberDetails(findMember);
    }

    private final class MemberDetails extends Member implements UserDetails{

        public MemberDetails(Member member) {
            setMemberId(member.getMemberId());
            setMemberStatus(member.getMemberStatus());
            setRoles(member.getRoles());
            setPassword(member.getPassword());
            setEmail(member.getEmail());
        }

        //DB에 있던 Role 정보를 전달하여 권한 목록을 생성
        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorityUtils.createAuthorities(this.getRoles());
        }

        //Spring Security에서 인식할 수 있는 username에 이메일을 저장한다.
        @Override
        public String getUsername() {
            return getEmail();
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }
}
