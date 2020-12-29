#pragma once

#include "network.h"
#include "player.h"
#include "session.h"

struct Bot {
  struct Connection conn;
  struct Session session;
  struct Player thePlayer;
};

struct Bot bot;
