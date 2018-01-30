drop procedure if exists alert_waf_count_day;

delimiter #

create procedure alert_waf_count_day 
(
IN insert_time INT,
IN alert VARCHAR(15)
) 
begin
declare period INT;
declare count_time INT;
declare count_id INT;

set period = 60 * 60 * 24;
set count_time = ceil(insert_time / period) * period;

select id into count_id from waf_count_day where time = count_time;

if count_id is not null then
		case alert
			when "disclosure" then
					update waf_count_day set disclosure = disclosure  + 1 where time = count_time;
			when "ddos" then
					update waf_count_day set ddos = ddos + 1 where time = count_time;
			when "reputation_ip" then
					update waf_count_day set reputation_ip = reputation_ip + 1 where time = count_time;
			when "lfi" then
					update waf_count_day set lfi = lfi + 1 where time = count_time;
			when "sqli" then
					update waf_count_day set sqli = sqli + 1 where time = count_time;
			when "xss" then
					update waf_count_day set xss = xss + 1 where time = count_time;
			when "injection_php" then
					update waf_count_day set injection_php = injection_php + 1 where time = count_time;
			when "generic" then
					update waf_count_day set generic = generic + 1 where time = count_time;
			when "rce" then
					update waf_count_day set rce = rce + 1 where time = count_time;
			when "protocol" then
					update waf_count_day set protocol = protocol + 1 where time = count_time;
			when "rfi" then
					update waf_count_day set rfi = rfi + 1 where time = count_time;
			when "fixation" then
					update waf_count_day set fixation = fixation + 1 where time = count_time;
			when "scaning" then
					update waf_count_day set scaning = scaning + 1 where time = count_time;
			else
					update waf_count_day set other = other + 1  where time = count_time;
		end case;
else
		case alert
			when "disclosure" then
					insert waf_count_day(time, disclosure) values (count_time, 1);
			when "ddos" then
					insert waf_count_day(time, ddos) values (count_time, 1);
			when "reputation_ip" then
					insert waf_count_day(time, reputation_ip) values (count_time, 1);
			when "lfi" then
					insert waf_count_day(time, lfi) values (count_time, 1);
			when "sqli" then
					insert waf_count_day(time, sqli) values (count_time, 1);
			when "xss" then
					insert waf_count_day(time, xss) values (count_time, 1);
			when "injection_php" then
					insert waf_count_day(time, injection_php) values (count_time, 1);
			when "generic" then
					insert waf_count_day(time, generic) values (count_time, 1);
			when "rce" then
					insert waf_count_day(time, rce) values (count_time, 1);
			when "protocol" then
					insert waf_count_day(time, protocol) values (count_time, 1);
			when "rfi" then
					insert waf_count_day(time, rfi) values (count_time, 1);
			when "fixation" then
					insert waf_count_day(time, fixation) values (count_time, 1);
			when "scaning" then
					insert waf_count_day(time, scaning) values (count_time, 1);
			else
					insert waf_count_day(time, other) values (count_time, 1);
		end case;

end if;

end# -- end of stored procedure block

delimiter ; -- switch delimiters again



DROP TRIGGER IF EXISTS `insert_waf`;
DELIMITER ;;
CREATE TRIGGER `insert_waf` AFTER INSERT ON `alert_waf` FOR EACH ROW BEGIN
	call alert_waf_count_day(NEW.time, NEW.attack);
END
;;
DELIMITER ;


drop procedure if exists alert_vds_count_day;

delimiter #

create procedure alert_vds_count_day 
(
IN insert_time INT,
IN alert VARCHAR(15)
) 
begin
declare period INT;
declare count_time INT;
declare count_id INT;

set period = 60 * 60 * 24;
set count_time = ceil(insert_time / period) * period;

select id into count_id from vds_count_day where time = count_time;

if count_id is not null then
		case alert
			when "backdoor" then
					update vds_count_day set backdoor = backdoor  + 1 where time = count_time;
			when "trojan" then
					update vds_count_day set trojan = trojan + 1 where time = count_time;
			when "risktool" then
					update vds_count_day set risktool = risktool + 1 where time = count_time;
			when "spyware" then
					update vds_count_day set spyware = spyware + 1 where time = count_time;
			when "malware" then
					update vds_count_day set malware = malware + 1 where time = count_time;
			when "virus" then
					update vds_count_day set virus = virus + 1 where time = count_time;
			when "worm" then
					update vds_count_day set worm = worm + 1 where time = count_time;
			when "joke" then
					update vds_count_day set joke = joke + 1 where time = count_time;
			when "adware" then
					update vds_count_day set adware = adware + 1 where time = count_time;
			when "hacktool" then
					update vds_count_day set hacktool = hacktool + 1 where time = count_time;
			when "exploit" then
					update vds_count_day set exploit = exploit + 1 where time = count_time;
			else
					update vds_count_day set other = other + 1  where time = count_time;
		end case;
else
		case alert
			when "backdoor" then
					insert vds_count_day(time, backdoor) values (count_time, 1);
			when "trojan" then
					insert vds_count_day(time, trojan) values (count_time, 1);
			when "risktool" then
					insert vds_count_day(time, risktool) values (count_time, 1);
			when "spyware" then
					insert vds_count_day(time, spyware) values (count_time, 1);
			when "malware" then
					insert vds_count_day(time, malware) values (count_time, 1);
			when "virus" then
					insert vds_count_day(time, virus) values (count_time, 1);
			when "worm" then
					insert vds_count_day(time, worm) values (count_time, 1);
			when "joke" then
					insert vds_count_day(time, joke) values (count_time, 1);
			when "adware" then
					insert vds_count_day(time, adware) values (count_time, 1);
			when "hacktool" then
					insert vds_count_day(time, hacktool) values (count_time, 1);
			when "exploit" then
					insert vds_count_day(time, exploit) values (count_time, 1);
			else
					insert vds_count_day(time, other) values (count_time, 1);
		end case;

end if;

end# -- end of stored procedure block

delimiter ; -- switch delimiters again



DROP TRIGGER IF EXISTS `insert_vds`;
DELIMITER ;;
CREATE TRIGGER `insert_vds` AFTER INSERT ON `alert_vds` FOR EACH ROW BEGIN
	call alert_vds_count_day(NEW.time, NEW.local_vtype);
END
;;
DELIMITER ;


drop procedure if exists alert_ids_count_day;

delimiter #

create procedure alert_ids_count_day 
(
IN insert_time INT,
IN alert VARCHAR(15)
) 
begin
declare period INT;
declare count_time INT;
declare count_id INT;

set period = 60 * 60 * 24;
set count_time = ceil(insert_time / period) * period;

select id into count_id from byzoro_ids_count where time = count_time;

if count_id is not null then
		case alert
			when "privilege_gain" then
					update byzoro_ids_count set privilege_gain = privilege_gain  + 1 where time = count_time;
			when "ddos" then
					update byzoro_ids_count set ddos = ddos + 1 where time = count_time;
			when "information_leak" then
					update byzoro_ids_count set information_leak = information_leak + 1 where time = count_time;
			when "web_attack" then
					update byzoro_ids_count set web_attack = web_attack + 1 where time = count_time;
			when "application_attack" then
					update byzoro_ids_count set application_attack = application_attack + 1 where time = count_time;
			when "candc" then
					update byzoro_ids_count set candc = candc + 1 where time = count_time;
			when "malware" then
					update byzoro_ids_count set malware = malware + 1 where time = count_time;
			when "misc_attack" then
					update byzoro_ids_count set misc_attack = misc_attack + 1 where time = count_time;
			else
					update byzoro_ids_count set other = other + 1  where time = count_time;
		end case;
else
		case alert
			when "privilege_gain" then
					insert byzoro_ids_count(time, privilege_gain) values (count_time, 1);
			when "ddos" then
					insert byzoro_ids_count(time, ddos) values (count_time, 1);
			when "information_leak" then
					insert byzoro_ids_count(time, information_leak) values (count_time, 1);
			when "web_attack" then
					insert byzoro_ids_count(time, web_attack) values (count_time, 1);
			when "application_attack" then
					insert byzoro_ids_count(time, application_attack) values (count_time, 1);
			when "candc" then
					insert byzoro_ids_count(time, candc) values (count_time, 1);
			when "malware" then
					insert byzoro_ids_count(time, malware) values (count_time, 1);
			when "misc_attack" then
					insert byzoro_ids_count(time, misc_attack) values (count_time, 1);
			else
					insert byzoro_ids_count(time, other) values (count_time, 1);
		end case;

end if;

end# -- end of stored procedure block

delimiter ; -- switch delimiters again



DROP TRIGGER IF EXISTS `insert_ids`;
DELIMITER ;;
CREATE TRIGGER `insert_ids` AFTER INSERT ON `alert_ids` FOR EACH ROW BEGIN
	call alert_ids_count_day(NEW.time, NEW.byzoro_type);
END
;;
DELIMITER ;


