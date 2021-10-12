﻿// <auto-generated />
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using WIMP_Server.Data;

namespace WIMP_Server.Migrations
{
    [DbContext(typeof(WimpDbContext))]
    [Migration("20211010075856_AddStargatesSystemModel")]
    partial class AddStargatesSystemModel
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "5.0.10");

            modelBuilder.Entity("WIMP_Server.Models.Character", b =>
                {
                    b.Property<int>("CharacterId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("CharacterId");

                    b.ToTable("Characters");
                });

            modelBuilder.Entity("WIMP_Server.Models.Intel", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<int>("CharacterId")
                        .HasColumnType("INTEGER");

                    b.Property<int?>("ReportedById")
                        .HasColumnType("INTEGER");

                    b.Property<int?>("ShipId")
                        .HasColumnType("INTEGER");

                    b.Property<int?>("StarGateId")
                        .HasColumnType("INTEGER");

                    b.Property<int>("StarSystemId")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("Timestamp")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("CharacterId");

                    b.HasIndex("ReportedById");

                    b.HasIndex("ShipId");

                    b.HasIndex("StarGateId");

                    b.HasIndex("StarSystemId");

                    b.ToTable("Intel");
                });

            modelBuilder.Entity("WIMP_Server.Models.Ship", b =>
                {
                    b.Property<int>("ShipId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("ShipId");

                    b.ToTable("Ships");
                });

            modelBuilder.Entity("WIMP_Server.Models.StarSystem", b =>
                {
                    b.Property<int>("StarSystemId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("StarSystemId");

                    b.ToTable("StarSystems");
                });

            modelBuilder.Entity("WIMP_Server.Models.Stargate", b =>
                {
                    b.Property<int>("StarGateId")
                        .HasColumnType("INTEGER");

                    b.Property<int>("DstStarSystemId")
                        .HasColumnType("INTEGER");

                    b.Property<int>("SrcStarSystemId")
                        .HasColumnType("INTEGER");

                    b.HasKey("StarGateId");

                    b.HasIndex("DstStarSystemId");

                    b.HasIndex("SrcStarSystemId");

                    b.ToTable("Stargate");
                });

            modelBuilder.Entity("WIMP_Server.Models.Intel", b =>
                {
                    b.HasOne("WIMP_Server.Models.Character", "Character")
                        .WithMany("Intel")
                        .HasForeignKey("CharacterId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("WIMP_Server.Models.Character", "ReportedBy")
                        .WithMany()
                        .HasForeignKey("ReportedById");

                    b.HasOne("WIMP_Server.Models.Ship", "Ship")
                        .WithMany("Intel")
                        .HasForeignKey("ShipId");

                    b.HasOne("WIMP_Server.Models.Stargate", null)
                        .WithMany("Intel")
                        .HasForeignKey("StarGateId");

                    b.HasOne("WIMP_Server.Models.StarSystem", "StarSystem")
                        .WithMany("Intel")
                        .HasForeignKey("StarSystemId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("Character");

                    b.Navigation("ReportedBy");

                    b.Navigation("Ship");

                    b.Navigation("StarSystem");
                });

            modelBuilder.Entity("WIMP_Server.Models.Stargate", b =>
                {
                    b.HasOne("WIMP_Server.Models.StarSystem", "DstStarSystem")
                        .WithMany("IncomingStargates")
                        .HasForeignKey("DstStarSystemId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("WIMP_Server.Models.StarSystem", "SrcStarSystem")
                        .WithMany("OutgoingStargates")
                        .HasForeignKey("SrcStarSystemId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("DstStarSystem");

                    b.Navigation("SrcStarSystem");
                });

            modelBuilder.Entity("WIMP_Server.Models.Character", b =>
                {
                    b.Navigation("Intel");
                });

            modelBuilder.Entity("WIMP_Server.Models.Ship", b =>
                {
                    b.Navigation("Intel");
                });

            modelBuilder.Entity("WIMP_Server.Models.StarSystem", b =>
                {
                    b.Navigation("IncomingStargates");

                    b.Navigation("Intel");

                    b.Navigation("OutgoingStargates");
                });

            modelBuilder.Entity("WIMP_Server.Models.Stargate", b =>
                {
                    b.Navigation("Intel");
                });
#pragma warning restore 612, 618
        }
    }
}
