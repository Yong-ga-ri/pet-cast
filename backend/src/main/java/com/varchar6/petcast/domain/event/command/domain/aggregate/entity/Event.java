package com.varchar6.petcast.domain.event.command.domain.aggregate.entity;

import com.varchar6.petcast.domain.event.command.domain.aggregate.EventStatusEnum;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import jakarta.persistence.*;

@Getter
@Setter
@Entity(name="eventEntity")
@Table(name = "tbl_event")
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Event {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "title", nullable = false)
    private String title;

    @Column(name = "content")
    private String content;

    @Column(name = "image")
    private String image;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private EventStatusEnum status;

    @Column(name = "company_id", nullable = false)
    private Integer companyId;

    @Column(name = "member_id", nullable = false)
    private Integer memberId;

}