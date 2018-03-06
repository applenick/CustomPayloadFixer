package ru.justblender.bukkit;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.events.PacketAdapter;
import com.comphenix.protocol.events.PacketContainer;
import com.comphenix.protocol.events.PacketEvent;
import com.comphenix.protocol.reflect.FuzzyReflection;
import com.comphenix.protocol.reflect.accessors.Accessors;
import com.comphenix.protocol.reflect.accessors.MethodAccessor;
import com.comphenix.protocol.reflect.fuzzy.FuzzyMethodContract;
import com.comphenix.protocol.utility.ByteBufferInputStream;
import com.comphenix.protocol.utility.MinecraftReflection;
import com.comphenix.protocol.utility.StreamSerializer;
import com.comphenix.protocol.wrappers.nbt.NbtCompound;
import com.comphenix.protocol.wrappers.nbt.NbtFactory;
import com.comphenix.protocol.wrappers.nbt.NbtList;
import com.google.common.base.Charsets;
import io.netty.buffer.ByteBuf;
import org.apache.commons.lang.Validate;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.inventory.ItemStack;
import org.bukkit.plugin.java.JavaPlugin;
import ru.justblender.PluginLogger.PluginLoggerHelper;

import java.io.DataInput;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.*;

/**
 * ****************************************************************
 * Copyright JustBlender (c) 2017. All rights reserved.
 * A code contained within this document, and any associated APIs with similar branding
 * are the sale property of JustBlender. Distribution, reproduction, taking snippets, or
 * claiming any contents as your own will break the terms of the license, and void any
 * agreements with you, the third party.
 * Thanks!
 * ****************************************************************
 */
public class CustomPayloadFixer extends JavaPlugin {

    // private static final Pattern COLOR_PATTERN = Pattern.compile("(?i)§[0-9A-FK-OR]");
    private static final Map<Player, Long> PACKET_USAGE = new ConcurrentHashMap<>();

    private String dispatchCommand, kickMessage;

    private static final Set<String> PACKET_NAMES = new HashSet<>(Arrays.asList("MC|BSign", "MC|BEdit", "REGISTER"));

    private Logger logger = null;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        if (getConfig().getBoolean("EnableCustomLog")) {
            try {
                logger = PluginLoggerHelper.openLogger(new File(getDataFolder(), "exploits.log"), getConfig().getString("CustomLogFormat"));
            } catch (Throwable ex) {
                getLogger().log(Level.SEVERE, ex.getMessage());
            }
        }

        dispatchCommand = getConfig().getString("dispatchCommand");
        kickMessage = getConfig().getString("kickMessage");

        ProtocolLibrary.getProtocolManager().addPacketListener(new PacketAdapter(this, PacketType.Play.Client.CUSTOM_PAYLOAD) {
            @Override
            public void onPacketReceiving(PacketEvent event) {
                checkPacket(event);
            }
        });

        Bukkit.getScheduler().runTaskTimer(this, () -> {
            for (Iterator<Map.Entry<Player, Long>> iterator = PACKET_USAGE.entrySet().iterator(); iterator.hasNext(); ) {
                Player player = iterator.next().getKey();
                if (!player.isOnline() || !player.isValid())
                    iterator.remove();
            }
        }, 20L, 20L);

        if (logger != null) logger.log(Level.INFO, "Plugin enabled");
    }

    @Override
    public void onDisable() {
        ProtocolLibrary.getProtocolManager().removePacketListeners(this);
        if (logger != null){
            logger.log(Level.INFO, "Plugin disabled");
            PluginLoggerHelper.closeLogger(logger);
        }
    }

    private void checkPacket(PacketEvent event) {
        Player player = event.getPlayer();
        if (player == null) {
            // Oh! Packet without player o_O. We can't do anything
            String name = event.getPacket().getStrings().readSafely(0);
            getLogger().log(Level.SEVERE, "packet ''{0}'' without player ", name);
            if (logger != null) logger.log(Level.SEVERE, "packet ''{0}'' without player ", name);
            event.setCancelled(true);
            return;
        }
        long lastPacket = PACKET_USAGE.getOrDefault(player, -1L);

        // This fucker is already detected as an exploiter
        if (lastPacket == -2L) {
            event.setCancelled(true);
            return;
        }

        String packetName = event.getPacket().getStrings().readSafely(0);
        if (packetName == null || !PACKET_NAMES.contains(packetName))
            return;

        try {
            if ("REGISTER".equals(packetName)) {
                checkChannels(event);
            } else {
                if (elapsed(lastPacket, 100L)) {
                    PACKET_USAGE.put(player, System.currentTimeMillis());
                } else {
                    throw new ExploitException("Packet flood");
                }

                checkNbtTags(event);
            }
        } catch (ExploitException ex) {
            // Set last packet usage to -2 so we wouldn't mind checking him again
            PACKET_USAGE.put(player, -2L);

            Bukkit.getScheduler().runTask(this, () -> {
                player.kickPlayer(kickMessage);

                if (dispatchCommand != null)
                    getServer().dispatchCommand(Bukkit.getConsoleSender(),
                            dispatchCommand.replace("%name%", player.getName()));
            });

            getLogger().warning(player.getName() + " tried to exploit CustomPayload: " + ex.getMessage());
            if (logger != null) logger.log(Level.WARNING, "{0} tried exploit CustomPayload: {1}{2}", new Object[]{player.getName(), ex.getMessage(), ex.itemstackToLogString(" ")});
            event.setCancelled(true);
        } catch (Throwable ex) {
            getLogger().severe(String.format("Failed to check packet '%s' for %s: %s", packetName, player.getName(), ex.getMessage()));
            if (logger != null) logger.log(Level.SEVERE, String.format("Failed to check packet '%s': ", packetName, player.getName()), ex);
            event.setCancelled(true);
        }
    }

    //@SuppressWarnings("deprecation")
    private void checkNbtTags(PacketEvent event) throws ExploitException {
        PacketContainer container = event.getPacket();
        ByteBuf buffer = container.getSpecificModifier(ByteBuf.class).read(0).copy();

        try {
            ItemStack itemStack = null;
            try {
                itemStack = deserializeItemStack(buffer);
            } catch (Throwable ex) {
                throw new ExploitException("Unable to deserialize ItemStack", ex);
            }
            if (itemStack == null)
                throw new ExploitException("Unable to deserialize ItemStack");

            NbtCompound root = (NbtCompound) NbtFactory.fromItemTag(itemStack);
            if (root == null)
                throw new ExploitException("No NBT tag?!", itemStack);

            if (!root.containsKey("pages"))
                throw new ExploitException("No 'pages' NBT compound was found", itemStack);

            NbtList<String> pages = root.getList("pages");
            if (pages.size() > 50)
                throw new ExploitException("Too much pages", itemStack);

            // This is for testing. Take a book, write on first page "CustomPayloadFixer" and either sign it or press done.
            if (pages.size() > 0 && "CustomPayloadFixer".equalsIgnoreCase(pages.getValue(0)))
                throw new ExploitException("Testing exploit", itemStack);

                /*
                Update 1: Here comes the funny part - Minecraft Wiki says that book allows to have only 256 symbols per page,
                but in reality it actually can get up to 257. What a jerks. (tested on 1.8.9)

                Update 2: Found one more exciting and surprisingly refreshing thing about Minecraft -
                Minecraft clients allow players to use § symbols in books. What the fuck, why?

                Update 3: I fucking hate Minecraft. Just why, whyy? Page length check is removed for now.

                for (String page : pages)
                    if (COLOR_PATTERN.matcher(page).replaceAll("").length() > 257)
                        throw new IOException("A very long page");
                */

        } finally {
            buffer.release();
        }
    }

    private void checkChannels(PacketEvent event) throws ExploitException {
        int channelsSize = event.getPlayer().getListeningPluginChannels().size();

        PacketContainer container = event.getPacket();
        ByteBuf buffer = container.getSpecificModifier(ByteBuf.class).read(0).copy();

        try {
            for (int i = 0; i < buffer.toString(Charsets.UTF_8).split("\0").length; i++)
                if (++channelsSize > 124)
                    throw new ExploitException("Too much channels");
        } finally {
            buffer.release();
        }
    }

    private boolean elapsed(long from, long required) {
        return from == -1L || System.currentTimeMillis() - from > required;
    }

    // This rewritten method deserializeItemStack from ProtocolLib
    // com.comphenix.protocol.utility.StreamSerializer.getDefault().deserializeItemStack(DataInputStream)
    // Input parameter has changed from DataInputStream to ByteBuf (to reduce code)
    private static MethodAccessor READ_ITEM_METHOD;
    private static MethodAccessor WRITE_ITEM_METHOD;
    public ItemStack deserializeItemStack(ByteBuf buf) throws IOException {
        Validate.notNull(buf, "input cannot be null!");
        Object nmsItem = null;
        if (MinecraftReflection.isUsingNetty()) {
            if (READ_ITEM_METHOD == null) {
                READ_ITEM_METHOD = Accessors.getMethodAccessor(FuzzyReflection.fromClass(MinecraftReflection.getPacketDataSerializerClass(), true).getMethodByParameters("readItemStack", MinecraftReflection.getItemStackClass(), new Class[0]));
            }

            Object serializer = MinecraftReflection.getPacketDataSerializer(buf);
            nmsItem = READ_ITEM_METHOD.invoke(serializer);
        } else {
            if (READ_ITEM_METHOD == null) {
                READ_ITEM_METHOD = Accessors.getMethodAccessor(FuzzyReflection.fromClass(MinecraftReflection.getPacketClass()).getMethod(FuzzyMethodContract.newBuilder().parameterCount(1).parameterDerivedOf(DataInput.class).returnDerivedOf(MinecraftReflection.getItemStackClass()).build()));
            }

            DataInputStream input = new DataInputStream(new ByteBufferInputStream(buf.nioBuffer()));
            nmsItem = READ_ITEM_METHOD.invoke((Object)null, new Object[]{input});
        }

        return nmsItem != null ? MinecraftReflection.getBukkitItemStack(nmsItem) : null;
    }
}
