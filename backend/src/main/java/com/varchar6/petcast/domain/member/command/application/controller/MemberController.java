package com.varchar6.petcast.domain.member.command.application.controller;

import com.varchar6.petcast.common.response.ResponseMessage;
import com.varchar6.petcast.domain.member.command.application.dto.request.MemberRequestDTO;
import com.varchar6.petcast.domain.member.command.application.dto.request.MemberUpdateRequestDTO;
import com.varchar6.petcast.domain.member.command.application.dto.request.ProfileRequestDTO;
import com.varchar6.petcast.domain.member.command.application.dto.request.ProfileUpdateRequestDTO;
import com.varchar6.petcast.domain.member.command.application.dto.response.MemberResponseDTO;
import com.varchar6.petcast.domain.member.command.application.dto.response.MemberUpdateResponseDTO;
import com.varchar6.petcast.domain.member.command.application.service.MemberService;
import com.varchar6.petcast.domain.member.command.application.vo.request.MemberUpdateRequestVO;
import com.varchar6.petcast.domain.member.command.application.vo.request.ProfileRegistRequestVO;
import com.varchar6.petcast.domain.member.command.application.vo.request.ProfileUpdateRequestVO;
import com.varchar6.petcast.domain.member.command.application.vo.request.RequestRegistUserVO;
import com.varchar6.petcast.domain.member.command.application.vo.response.MemberUpdateResponseVO;
import com.varchar6.petcast.domain.member.command.application.vo.response.ResponseRegistUserVO;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.awt.*;
import java.util.List;

@RestController(value = "commandMemberController")
@RequestMapping("/api/v1/members")
@Slf4j
public class MemberController {

    private final MemberService memberService;
    private final ModelMapper modelMapper;

    @Autowired
    public MemberController(MemberService memberService, ModelMapper modelMapper) {
        this.memberService = memberService;
        this.modelMapper = modelMapper;
    }

    @GetMapping("/test")
    public String getTest(
//            @RequestAttribute("memberId") int memberId,
//            @RequestAttribute("memberLoginId") String memberLoginId,
//            @RequestAttribute("memberName") String name,
//            @RequestAttribute("memberPhone") String memberPhone,
//            @RequestAttribute("memberNickname") String memberNickname,
//            @RequestAttribute("image") String image,
//            @RequestAttribute("created") String created,
//            @RequestAttribute("updated") String updated,
//            @RequestAttribute("active") boolean active,
//            @RequestAttribute("introduction") String introduction,
//            @RequestAttribute("authorities") List<String> authorities
    ) {
//        log.debug("memberId: {}", memberId);
//        log.debug("memberLoginId: {}", memberLoginId);
//        log.debug("created: {}", created);
//        log.debug("active: {}", active);
//        log.debug("authorities: {}", authorities);

        return "GET working";
    }

    @PostMapping("/test")
    public String postTest() {
        return "POST working";
    }

    @PostMapping("/sign-up")
    public ResponseEntity<ResponseMessage> signUp(@RequestBody RequestRegistUserVO newUser) {

        MemberRequestDTO memberRequestDTO = modelMapper.map(newUser, MemberRequestDTO.class);

        MemberResponseDTO memberResponseDTO = memberService.registerMember(memberRequestDTO);

        ResponseRegistUserVO responseMember = modelMapper.map(memberResponseDTO, ResponseRegistUserVO.class);

        return ResponseEntity
                .ok()
                .body(
                        ResponseMessage.builder()
                                .httpStatus(HttpStatus.CREATED.value())
                                .message("Login completed")
                                .result(responseMember)
                                .build()
                );
    }

    @PostMapping("/update-member-status")
    public ResponseEntity<ResponseMessage> updateMemberStatus(@RequestAttribute("memberId") int memberId) {

        MemberUpdateRequestDTO updateStatus = new MemberUpdateRequestDTO();

        updateStatus.setId(memberId);

        MemberUpdateRequestDTO memberUpdateRequestDTO
                = modelMapper.map(updateStatus, MemberUpdateRequestDTO.class);

        MemberUpdateResponseDTO memberUpdateResponseDTO = memberService.updateMemberStatus(memberUpdateRequestDTO);

        MemberUpdateResponseVO responseMember = modelMapper.map(memberUpdateResponseDTO, MemberUpdateResponseVO.class);

        return ResponseEntity
                .ok()
                .body(ResponseMessage.builder()
                        .httpStatus(HttpStatus.OK.value())
                        .message("회원 비활성화 성공")
                        .result(responseMember)
                        .build());
    }

    @PutMapping("/update-password")
    public ResponseEntity<ResponseMessage> updateMemberPassword(@RequestBody MemberUpdateRequestVO updateMember,
                                                                @RequestAttribute("memberId") int memberId) {

        updateMember.setId(memberId);

        MemberUpdateRequestDTO memberUpdateRequestDTO = modelMapper.map(updateMember, MemberUpdateRequestDTO.class);

        MemberUpdateResponseDTO memberUpdateResponseDTO = memberService.updateMemberPwd(memberUpdateRequestDTO);

        MemberUpdateResponseVO responseMember = modelMapper.map(memberUpdateResponseDTO, MemberUpdateResponseVO.class);

        return ResponseEntity
                .ok()
                .body(ResponseMessage.builder()
                        .httpStatus(HttpStatus.CREATED.value())
                        .message("회원 암호 변경 성공")
                        .result(responseMember)
                        .build());
    }

    @PostMapping("/regist-member-profile")
    public ResponseEntity<ResponseMessage> registMemberProfile(@RequestBody ProfileRegistRequestVO newProfile,
                                                               @RequestAttribute("memberId") int memberId) {

        newProfile.setMemberId(memberId);

        ProfileRequestDTO profileRequestDTO = modelMapper.map(newProfile, ProfileRequestDTO.class);

        Boolean answer = memberService.registMemberProfile(profileRequestDTO);

        return ResponseEntity
                .ok()
                .body(ResponseMessage.builder()
                        .httpStatus(HttpStatus.CREATED.value())
                        .message("고객 프로필 생성 성공")
                        .result(answer)
                        .build());
    }

    @PutMapping("/update-member-profile")
    public ResponseEntity<ResponseMessage> updateMemberProfile(@RequestBody ProfileUpdateRequestVO updateProfile,
                                                               @RequestAttribute("memberId") int memberId) {
        updateProfile.setMemberId(memberId);

        ProfileUpdateRequestDTO profileUpdateRequestDTO = modelMapper.map(updateProfile, ProfileUpdateRequestDTO.class);

        Boolean answer = memberService.updateMemberProfile(profileUpdateRequestDTO);

        return ResponseEntity
                .ok()
                .body(ResponseMessage.builder()
                        .httpStatus(HttpStatus.OK.value())
                        .message("고객 프로필 수정 성공")
                        .result(answer)
                        .build());
    }
}
