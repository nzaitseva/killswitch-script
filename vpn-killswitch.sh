#!/bin/bash
#
# vpn-killswitch.sh — VPN kill switch для macOS на базе pf (Packet Filter).
#
# Когда kill switch включён, блокируется весь трафик, кроме:
#   - трафика к IP-адресу(ам) VPN-сервера (чтобы туннель мог подняться);
#   - трафика через туннельные интерфейсы (utun*, ipsec*, ppp*, tun*);
#   - loopback (lo0) и DHCP (чтобы не терять адрес в Wi-Fi/Ethernet);
#   - локальной сети — только с флагом --allow-lan.
# Если VPN отвалится, трафик мимо туннеля просто перестанет ходить.
#
# Правила грузятся в отдельный anchor внутри системного "com.apple/*",
# поэтому /etc/pf.conf не меняется, а включение/выключение работает
# на лету, без перезагрузки. После перезагрузки kill switch выключен.
#
# Использование:
#   sudo ./vpn-killswitch.sh --start <VPN_SERVER_IP> [IP2 ...] [--allow-lan]
#   sudo ./vpn-killswitch.sh --stop
#   sudo ./vpn-killswitch.sh --status
#   sudo ./vpn-killswitch.sh --install    # установить как команду vpn-killswitch
#   sudo vpn-killswitch --uninstall       # удалить команду

set -eo pipefail

# Имя начинается с "000.", чтобы anchor проверялся раньше системных
# (com.apple/200.AirDrop, com.apple/250.ApplicationFirewall и т.д.).
ANCHOR="com.apple/000.vpn_killswitch"
STATE_DIR="/var/run/vpn-killswitch"
TOKEN_FILE="$STATE_DIR/pf.token"
RULES_FILE="$STATE_DIR/rules.conf"
# Куда ставится команда. /usr/local/bin по умолчанию есть в PATH (см. /etc/paths).
INSTALL_PATH="/usr/local/bin/vpn-killswitch"

# Интерфейсы VPN-туннелей. Несуществующие имена pf спокойно принимает,
# правило сработает, когда интерфейс появится.
TUN_IFS=""
for i in $(seq 0 31); do TUN_IFS+="utun$i, "; done
for i in $(seq 0 7); do TUN_IFS+="ipsec$i, ppp$i, tun$i, "; done
TUN_IFS="{ ${TUN_IFS%, } }"

LAN_NETS="{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255, fe80::/10, ff00::/8 }"

usage() {
	cat <<EOF
Использование:
  $(basename "$0") --start <VPN_SERVER_IP> [IP2 ...] [--allow-lan]
  $(basename "$0") --stop
  $(basename "$0") --status
  $(basename "$0") --install | --uninstall

  --start      включить kill switch: трафик только через VPN или к IP сервера
  --stop       выключить kill switch и вернуть всё как было
  --status     показать, включён ли kill switch и какие правила действуют
  --allow-lan  (с --start) разрешить локальную сеть: роутер, принтеры, AirDrop
  --install    установить как команду: дальше запускать как «sudo vpn-killswitch ...»
               из любой папки ($INSTALL_PATH)
  --uninstall  удалить установленную команду
  -h, --help   эта справка

IP можно перечислить через пробел или через запятую.
Требуются права root (скрипт сам перезапустится через sudo).
EOF
}

die() {
	echo "Ошибка: $*" >&2
	exit 1
}

is_ipv4() {
	local ip=$1 octet
	[[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
	local IFS=.
	for octet in $ip; do
		((10#$octet <= 255)) || return 1
	done
}

is_ipv6() {
	[[ $1 == *:* && $1 =~ ^[0-9A-Fa-f:.]+$ ]]
}

# Запускает pfctl, убирая шум про ALTQ; при ошибке печатает вывод и падает.
run_pfctl() {
	local out
	if ! out=$(pfctl "$@" 2>&1); then
		echo "$out" | grep -v -e 'ALTQ' >&2
		die "pfctl $* завершился с ошибкой"
	fi
	echo "$out" | grep -v -e 'ALTQ' -e 'Use of -f option' -e 'present in the main ruleset' -e 'See /etc/pf.conf' -e '^$' || true
}

is_active() {
	[[ -n $(pfctl -a "$ANCHOR" -sr 2>/dev/null) ]]
}

gen_rules() {
	local allow_lan=$1
	shift
	local servers
	servers=$(printf '%s, ' "$@")
	servers="{ ${servers%, } }"

	cat <<EOF
# Сгенерировано vpn-killswitch.sh $(date '+%Y-%m-%d %H:%M:%S')
tun_ifs = "$TUN_IFS"
vpn_servers = "$servers"
lan_nets = "$LAN_NETS"

# Правила без состояний (no state): так уже установленные соединения
# через туннель не рвутся в момент включения.

# loopback
pass quick on lo0 all no state

# всё, что идёт через VPN-туннель
pass quick on \$tun_ifs all no state

# соединение с самим VPN-сервером (любой протокол: UDP, TCP, ESP...)
pass out quick to \$vpn_servers no state
pass in  quick from \$vpn_servers no state

# DHCP, чтобы не потерять IP-адрес в локальной сети
pass out quick proto udp from any port 68 to any port 67 no state
pass in  quick proto udp from any port 67 to any port 68 no state
EOF

	if ((allow_lan)); then
		cat <<'EOF'

# локальная сеть (--allow-lan)
pass out quick to $lan_nets no state
pass in  quick from $lan_nets no state
EOF
	fi

	cat <<'EOF'

# всё остальное — запрещено (исходящее отклоняем сразу, чтобы приложения
# не висели по таймауту, входящее молча отбрасываем)
block return out quick all
block drop   in  quick all
EOF
}

start() {
	local allow_lan=$1
	shift

	mkdir -p "$STATE_DIR"
	chmod 700 "$STATE_DIR"
	gen_rules "$allow_lan" "$@" >"$RULES_FILE"

	# Сначала проверяем синтаксис, ничего не применяя.
	run_pfctl -n -a "$ANCHOR" -f "$RULES_FILE" >/dev/null

	# Наш anchor вызывается из 'anchor "com.apple/*"' основного набора правил.
	# Если кто-то сбросил основной набор — восстанавливаем системный.
	if ! pfctl -sr 2>/dev/null | grep -q 'anchor "com.apple/\*"'; then
		echo "Основной набор правил pf без anchor com.apple — загружаю /etc/pf.conf"
		run_pfctl -f /etc/pf.conf >/dev/null
	fi

	run_pfctl -a "$ANCHOR" -f "$RULES_FILE" >/dev/null

	# Включаем pf со своей ссылкой (token): при --stop отпустим только её,
	# и pf выключится, только если он больше никому не нужен.
	if [[ ! -s $TOKEN_FILE ]]; then
		local out token
		out=$(pfctl -E 2>&1) || {
			echo "$out" >&2
			die "не удалось включить pf"
		}
		token=$(echo "$out" | sed -n 's/^Token : \([0-9][0-9]*\).*/\1/p')
		[[ -n $token ]] || die "не удалось получить token от pfctl -E"
		echo "$token" >"$TOKEN_FILE"
	fi

	# Сбрасываем старые состояния, чтобы уже открытые соединения мимо VPN
	# (если pf был включён кем-то раньше) не продолжили работать.
	run_pfctl -F states >/dev/null

	echo "Kill switch ВКЛЮЧЁН. Разрешён трафик через VPN-туннель и к: $*"
	((allow_lan)) && echo "Локальная сеть разрешена."
	echo "Выключить: sudo $(basename "$0") --stop"
}

stop() {
	local was_active=0
	is_active && was_active=1

	run_pfctl -a "$ANCHOR" -F rules >/dev/null

	if [[ -s $TOKEN_FILE ]]; then
		pfctl -X "$(cat "$TOKEN_FILE")" >/dev/null 2>&1 ||
			echo "Предупреждение: не удалось отпустить token pf (возможно, был перезапуск)" >&2
	fi
	rm -rf "$STATE_DIR"

	if ((was_active)); then
		echo "Kill switch ВЫКЛЮЧЕН. Трафик снова идёт как обычно."
	else
		echo "Kill switch и так не был включён."
	fi
}

status() {
	if is_active; then
		echo "Kill switch: ВКЛЮЧЁН"
		echo
		echo "Правила (anchor $ANCHOR):"
		pfctl -a "$ANCHOR" -sr 2>/dev/null
	else
		echo "Kill switch: выключен"
	fi
	echo
	pfctl -s info 2>/dev/null | grep '^Status' || true
}

install_self() {
	local src
	src="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
	if [[ $src == "$INSTALL_PATH" ]]; then
		echo "Это уже установленная копия ($INSTALL_PATH)."
		return
	fi
	mkdir -p "$(dirname "$INSTALL_PATH")"
	# Копия принадлежит root и недоступна для записи обычному пользователю:
	# скрипт запускается через sudo, и подменить его никто не должен.
	install -m 755 -o root -g wheel "$src" "$INSTALL_PATH"
	echo "Установлено: $INSTALL_PATH"
	echo "Теперь из любой папки: sudo vpn-killswitch --start <IP> | --stop | --status"
	echo "После изменения скрипта запустите --install ещё раз, чтобы обновить копию."
}

uninstall_self() {
	if is_active; then
		die "kill switch сейчас включён — сначала выполните: sudo $(basename "$0") --stop"
	fi
	if [[ ! -e $INSTALL_PATH ]]; then
		echo "Команда не установлена ($INSTALL_PATH не найден)."
		return
	fi
	rm -f "$INSTALL_PATH"
	echo "Удалено: $INSTALL_PATH"
}

# --- разбор аргументов ---

[[ $# -gt 0 ]] || {
	usage
	exit 1
}
orig_args=("$@")

action=""
allow_lan=0
ips=()
while [[ $# -gt 0 ]]; do
	case $1 in
	--start | --stop | --status | --install | --uninstall)
		[[ -z $action ]] || die "укажите только одно действие (--start, --stop, --status, --install, --uninstall)"
		action=${1#--}
		;;
	--allow-lan) allow_lan=1 ;;
	-h | --help)
		usage
		exit 0
		;;
	-*) die "неизвестный флаг: $1 (см. --help)" ;;
	*)
		IFS=, read -r -a parts <<<"$1"
		for ip in "${parts[@]}"; do
			[[ -n $ip ]] || continue
			is_ipv4 "$ip" || is_ipv6 "$ip" || die "некорректный IP-адрес: $ip"
			ips+=("$ip")
		done
		;;
	esac
	shift
done

[[ -n $action ]] || die "нужен один из флагов --start, --stop, --status, --install, --uninstall (см. --help)"
if [[ $action == start && ${#ips[@]} -eq 0 ]]; then
	die "для --start укажите IP-адрес VPN-сервера"
fi
if [[ $action != start && (${#ips[@]} -gt 0 || $allow_lan -eq 1) ]]; then
	die "IP-адреса и --allow-lan используются только с --start"
fi

if [[ $EUID -ne 0 ]]; then
	exec sudo /bin/bash "$0" "${orig_args[@]}"
fi

case $action in
start) start "$allow_lan" "${ips[@]}" ;;
stop) stop ;;
status) status ;;
install) install_self ;;
uninstall) uninstall_self ;;
esac
